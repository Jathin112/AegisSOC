import { NormalizedAuthLog, UserBaseline, DetectionRule, DetectionAlert } from '../types';
import { extractSubnet } from './baselineLearner';

export function runDetectionRules(
  allLogs: NormalizedAuthLog[],
  baselines: Map<string, UserBaseline>,
  rules: DetectionRule[]
): DetectionAlert[] {
  const alerts: DetectionAlert[] = [];
  const rulesMap = new Map<string, DetectionRule>();
  rules.forEach(r => rulesMap.set(r.category, r));

  // Sort logs chronologically
  const sortedLogs = [...allLogs].sort((a, b) => a.epochMs - b.epochMs);
  // Group logs by user
  const userLogsMap = new Map<string, NormalizedAuthLog[]>();
  for (const log of sortedLogs) {
    const u = log.user.toLowerCase().trim();
    if (!userLogsMap.has(u)) userLogsMap.set(u, []);
    userLogsMap.get(u)!.push(log);
  }

  // Group logs by IP (for password spray detection)
  const ipLogsMap = new Map<string, NormalizedAuthLog[]>();
  for (const log of sortedLogs) {
    const ip = log.ip.trim();
    if (!ip) continue;
    if (!ipLogsMap.has(ip)) ipLogsMap.set(ip, []);
    ipLogsMap.get(ip)!.push(log);
  }

  // 1. REPEATED FAILURES (BRUTE FORCE)
  const repeatedRule = rulesMap.get('REPEATED_FAILURES');
  if (repeatedRule && repeatedRule.enabled) {
    const threshold = repeatedRule.params.repeatedFailuresThreshold || 4;
    const windowMs = (repeatedRule.params.repeatedFailuresWindowMinutes || 10) * 60 * 1000;

    userLogsMap.forEach((userLogs, username) => {
      // Find sliding windows of failures
      const failureLogs = userLogs.filter(l => l.action === 'FAILURE');
      if (failureLogs.length < threshold) return;

      const flaggedLogIds = new Set<string>();

      for (let i = 0; i < failureLogs.length; i++) {
        const windowStart = failureLogs[i].epochMs;
        const windowEnd = windowStart + windowMs;
        const inWindow = failureLogs.slice(i).filter(l => l.epochMs <= windowEnd);

        if (inWindow.length >= threshold) {
          const unflagged = inWindow.filter(l => !flaggedLogIds.has(l.id));
          if (unflagged.length >= threshold) {
            inWindow.forEach(l => flaggedLogIds.add(l.id));
            const targetedHosts = Array.from(new Set(inWindow.map(l => l.host)));
            const sourceIps = Array.from(new Set(inWindow.map(l => l.ip)));

            alerts.push({
              id: `ALT-RF-${username}-${failureLogs[i].id}`,
              ruleId: repeatedRule.id,
              ruleCategory: 'REPEATED_FAILURES',
              ruleName: repeatedRule.name,
              user: inWindow[0].user,
              timestamp: inWindow[inWindow.length - 1].timestamp,
              severity: repeatedRule.severity,
              threatClass: repeatedRule.threatClass,
              score: repeatedRule.baseWeight,
              summary: `${inWindow.length} consecutive authentication failures detected within ${repeatedRule.params.repeatedFailuresWindowMinutes} minutes across ${targetedHosts.join(', ')} from IP(s): ${sourceIps.join(', ')}.`,
              evidence: inWindow,
              details: {
                failureCount: inWindow.length,
                timeWindowMinutes: repeatedRule.params.repeatedFailuresWindowMinutes,
                hosts: targetedHosts,
                ips: sourceIps
              }
            });
          }
        }
      }
    });
  }

  // 2. BURST OF FAILURES FOLLOWED BY SUCCESS
  const burstRule = rulesMap.get('BURST_FAILURE_THEN_SUCCESS');
  if (burstRule && burstRule.enabled) {
    const minFailures = burstRule.params.burstFailuresMinCount || 3;
    const windowMs = (burstRule.params.burstSuccessWindowMinutes || 15) * 60 * 1000;

    userLogsMap.forEach((userLogs, username) => {
      for (let i = 0; i < userLogs.length; i++) {
        if (userLogs[i].action === 'SUCCESS') {
          const successLog = userLogs[i];
          const windowStart = successLog.epochMs - windowMs;

          // Look backwards for preceding failures
          const precedingFailures = userLogs
            .slice(0, i)
            .filter(l => l.epochMs >= windowStart && l.epochMs <= successLog.epochMs && l.action === 'FAILURE');

          if (precedingFailures.length >= minFailures) {
            const evidence = [...precedingFailures, successLog];
            alerts.push({
              id: `ALT-BURST-${username}-${successLog.id}`,
              ruleId: burstRule.id,
              ruleCategory: 'BURST_FAILURE_THEN_SUCCESS',
              ruleName: burstRule.name,
              user: successLog.user,
              timestamp: successLog.timestamp,
              severity: burstRule.severity,
              threatClass: burstRule.threatClass, // CONFIRMED_COMPROMISE!
              score: burstRule.baseWeight,
              summary: `CRITICAL: ${precedingFailures.length} failed attempts immediately followed by a SUCCESSFUL login within ${burstRule.params.burstSuccessWindowMinutes} mins. Strong evidence of credential cracking or unauthorized access.`,
              evidence,
              details: {
                priorFailures: precedingFailures.length,
                successHost: successLog.host,
                successIp: successLog.ip,
                successTimestamp: successLog.timestamp
              }
            });
          }
        }
      }
    });
  }

  // 3. HORIZONTAL PASSWORD SPRAYING
  const sprayRule = rulesMap.get('PASSWORD_SPRAY');
  if (sprayRule && sprayRule.enabled) {
    const minUsers = sprayRule.params.sprayDistinctUsersMin || 3;
    const windowMs = (sprayRule.params.sprayWindowMinutes || 20) * 60 * 1000;

    ipLogsMap.forEach((ipLogs, sourceIp) => {
      // Ignore private localhost if desired, but check corporate subnets or external IPs
      for (let i = 0; i < ipLogs.length; i++) {
        const startMs = ipLogs[i].epochMs;
        const endMs = startMs + windowMs;
        const inWindow = ipLogs.slice(i).filter(l => l.epochMs <= endMs);
        const distinctUsers = Array.from(new Set(inWindow.map(l => l.user.toLowerCase().trim())));

        if (distinctUsers.length >= minUsers) {
          // Check if mostly failures
          const failureCount = inWindow.filter(l => l.action === 'FAILURE').length;
          if (failureCount >= distinctUsers.length) {
            // Generate alert for each affected user or group alert
            distinctUsers.forEach(u => {
              const userEvidence = inWindow.filter(l => l.user.toLowerCase().trim() === u);
              alerts.push({
                id: `ALT-SPRAY-${sourceIp.replace(/[^a-zA-Z0-9]/g, '_')}-${u}-${ipLogs[i].id}`,
                ruleId: sprayRule.id,
                ruleCategory: 'PASSWORD_SPRAY',
                ruleName: sprayRule.name,
                user: u,
                timestamp: inWindow[inWindow.length - 1].timestamp,
                severity: sprayRule.severity,
                threatClass: sprayRule.threatClass,
                score: sprayRule.baseWeight,
                summary: `Source IP ${sourceIp} executed horizontal password spray targeting ${distinctUsers.length} accounts (${distinctUsers.slice(0, 4).join(', ')}${distinctUsers.length > 4 ? '...' : ''}) within ${sprayRule.params.sprayWindowMinutes} mins.`,
                evidence: inWindow,
                details: {
                  sourceIp,
                  totalTargetedUsers: distinctUsers.length,
                  targetedUsersList: distinctUsers,
                  failureRatio: `${failureCount}/${inWindow.length}`
                }
              });
            });
            break; // Stop further overlapping alerts for this IP burst
          }
        }
      }
    });
  }

  // 4. UNUSUAL LOGIN TIMES (Off-hours anomaly)
  const timeRule = rulesMap.get('UNUSUAL_TIME');
  if (timeRule && timeRule.enabled) {
    // Only check logs outside training period to avoid self-flagging training baseline
    const evalLogs = sortedLogs.filter(l => !l.inTrainingPeriod);

    for (const log of evalLogs) {
      const uKey = log.user.toLowerCase().trim();
      const baseline = baselines.get(uKey);
      if (!baseline || baseline.totalEvents < 3) continue;

      const hour = log.dateObj.getUTCHours();
      const isUsualHour = baseline.usualHours.includes(hour);

      if (!isUsualHour) {
        alerts.push({
          id: `ALT-TIME-${uKey}-${log.id}`,
          ruleId: timeRule.id,
          ruleCategory: 'UNUSUAL_TIME',
          ruleName: timeRule.name,
          user: log.user,
          timestamp: log.timestamp,
          severity: timeRule.severity,
          threatClass: timeRule.threatClass,
          score: timeRule.baseWeight,
          summary: `Login occurred at UTC ${hour.toString().padStart(2, '0')}:00, an hour with ZERO recorded baseline activity (normal hours: ${baseline.usualHours.map(h => `${h}:00`).join(', ')}).`,
          evidence: [log],
          details: {
            observedHour: hour,
            usualHours: baseline.usualHours,
            action: log.action,
            host: log.host,
            ip: log.ip
          }
        });
      }
    }
  }

  // 5. UNFAMILIAR IPS / SUBNETS
  const ipRule = rulesMap.get('UNFAMILIAR_IP');
  if (ipRule && ipRule.enabled) {
    const evalLogs = sortedLogs.filter(l => !l.inTrainingPeriod);

    for (const log of evalLogs) {
      const uKey = log.user.toLowerCase().trim();
      const baseline = baselines.get(uKey);
      if (!baseline || baseline.totalEvents < 2) continue;

      const logSubnet = extractSubnet(log.ip);
      const isKnownIp = baseline.usualIPs.includes(log.ip);
      const isKnownSubnet = baseline.usualSubnets.includes(logSubnet);

      const isUnfamiliar = ipRule.params.subnetMatchOnly ? !isKnownSubnet : !isKnownIp;

      if (isUnfamiliar) {
        alerts.push({
          id: `ALT-IP-${uKey}-${log.id}`,
          ruleId: ipRule.id,
          ruleCategory: 'UNFAMILIAR_IP',
          ruleName: ipRule.name,
          user: log.user,
          timestamp: log.timestamp,
          severity: ipRule.severity,
          threatClass: ipRule.threatClass,
          score: ipRule.baseWeight,
          summary: `Authentication from unfamiliar IP address ${log.ip} (${log.location || 'Unknown Geo'}, Subnet: ${logSubnet}) not present in baseline profile.`,
          evidence: [log],
          details: {
            observedIp: log.ip,
            observedLocation: log.location,
            baselineUsualIps: baseline.usualIPs,
            baselineUsualSubnets: baseline.usualSubnets
          }
        });
      }
    }
  }

  // 6. SUDDEN HOST ACCESS EXPANSION (LATERAL MOVEMENT)
  const hostRule = rulesMap.get('HOST_EXPANSION');
  if (hostRule && hostRule.enabled) {
    const evalLogs = sortedLogs.filter(l => !l.inTrainingPeriod && l.action === 'SUCCESS');
    const threshold = hostRule.params.hostExpansionNewHostsThreshold || 1;
    const windowMs = (hostRule.params.hostExpansionWindowMinutes || 60) * 60 * 1000;

    userLogsMap.forEach((userLogs, username) => {
      const baseline = baselines.get(username);
      if (!baseline || baseline.totalEvents < 2) return;

      const evalUserLogs = userLogs.filter(l => !l.inTrainingPeriod && l.action === 'SUCCESS');
      const unfamiliarHostLogs = evalUserLogs.filter(
        l => !baseline.usualHosts.includes(l.host.toUpperCase().trim())
      );

      if (unfamiliarHostLogs.length === 0) return;

      // Check in sliding window
      for (let i = 0; i < unfamiliarHostLogs.length; i++) {
        const startMs = unfamiliarHostLogs[i].epochMs;
        const endMs = startMs + windowMs;
        const inWindow = unfamiliarHostLogs.slice(i).filter(l => l.epochMs <= endMs);
        const distinctNewHosts = Array.from(new Set(inWindow.map(l => l.host.toUpperCase().trim())));

        if (distinctNewHosts.length >= threshold) {
          alerts.push({
            id: `ALT-HOST-${username}-${unfamiliarHostLogs[i].id}`,
            ruleId: hostRule.id,
            ruleCategory: 'HOST_EXPANSION',
            ruleName: hostRule.name,
            user: unfamiliarHostLogs[i].user,
            timestamp: inWindow[inWindow.length - 1].timestamp,
            severity: hostRule.severity,
            threatClass: hostRule.threatClass,
            score: hostRule.baseWeight,
            summary: `Lateral access expansion: User successfully accessed ${distinctNewHosts.length} new host(s) (${distinctNewHosts.join(', ')}) never accessed during baseline (Authorized: ${baseline.usualHosts.join(', ')}).`,
            evidence: inWindow,
            details: {
              newHosts: distinctNewHosts,
              baselineHosts: baseline.usualHosts,
              windowMinutes: hostRule.params.hostExpansionWindowMinutes
            }
          });
          break; // Stop duplicate cascades
        }
      }
    });
  }

  return alerts;
}
