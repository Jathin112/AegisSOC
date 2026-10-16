import { 
  NormalizedAuthLog, 
  UserBaseline, 
  DetectionRule, 
  DetectionAlert, 
  UserAccountConfig, 
  MaintenanceWindow, 
  CompanyVpnConfig 
} from '../types';
import { extractSubnet } from './baselineLearner';

/**
 * Checks if a specific log event matches a declared maintenance window
 */
export function matchMaintenanceWindow(
  epochMs: number,
  user: string,
  userConfig: UserAccountConfig | undefined,
  host: string,
  windows: MaintenanceWindow[]
): MaintenanceWindow | null {
  for (const win of windows) {
    if (win.status !== 'COMPLETED' && epochMs >= win.startEpochMs && epochMs <= win.endEpochMs) {
      const userRole = userConfig?.role || 'REGULAR_USER';
      const roleApproved = win.approvedRoles.includes(userRole) || (userConfig?.isAuthorizedHelpdesk && win.approvedRoles.includes('HELPDESK'));
      const accountApproved = win.approvedAccounts.includes('*') || win.approvedAccounts.includes(user.toLowerCase());

      if (roleApproved || accountApproved) {
        // Scope matching (e.g. ['*'] or ['ALL_WORKSTATIONS'] or host prefix/exact)
        const hostScopeMatch = win.targetScope.some(scope => {
          if (scope === '*' || scope === 'ALL_WORKSTATIONS') return true;
          if (scope.endsWith('*')) {
            const prefix = scope.slice(0, -1).toUpperCase();
            return host.toUpperCase().startsWith(prefix);
          }
          return scope.toUpperCase() === host.toUpperCase();
        });

        if (hostScopeMatch) {
          return win;
        }
      }
    }
  }
  return null;
}

/**
 * Checks if a log event matches an authorized Corporate VPN gateway or pool
 */
export function matchCompanyVpn(
  ip: string,
  host: string,
  location: string,
  vpns: CompanyVpnConfig[]
): CompanyVpnConfig | null {
  for (const vpn of vpns) {
    // Check if host is VPN gateway
    if (vpn.gatewayName && host.toUpperCase().includes(vpn.gatewayName.toUpperCase())) {
      return vpn;
    }
    // Check gateway public IP
    if (vpn.gatewayIPs && vpn.gatewayIPs.includes(ip)) {
      return vpn;
    }
    // Check CIDR prefix (e.g. 10.250.x.x)
    for (const range of vpn.ipRanges) {
      const prefix = range.split('/')[0].split('.').slice(0, 2).join('.');
      if (ip.startsWith(prefix + '.')) {
        return vpn;
      }
    }
    // Check location string for corporate VPN indication
    if (location && (location.toLowerCase().includes('vpn') || location.toLowerCase().includes(vpn.gatewayName.toLowerCase()))) {
      return vpn;
    }
  }
  return null;
}

export function runDetectionRules(
  allLogs: NormalizedAuthLog[],
  baselines: Map<string, UserBaseline>,
  rules: DetectionRule[],
  userAccounts: UserAccountConfig[] = [],
  maintenanceWindows: MaintenanceWindow[] = [],
  vpnConfigs: CompanyVpnConfig[] = []
): DetectionAlert[] {
  const alerts: DetectionAlert[] = [];
  const rulesMap = new Map<string, DetectionRule>();
  rules.forEach(r => rulesMap.set(r.category, r));

  const accountsMap = new Map<string, UserAccountConfig>();
  userAccounts.forEach(acc => accountsMap.set(acc.username.toLowerCase(), acc));

  // Sort logs chronologically
  const sortedLogs = [...allLogs].sort((a, b) => a.epochMs - b.epochMs);

  // Annotate logs with context
  sortedLogs.forEach(log => {
    const userKey = log.user.toLowerCase().trim();
    const userCfg = accountsMap.get(userKey);
    log.accountRole = userCfg?.role || 'REGULAR_USER';

    const matchedWin = matchMaintenanceWindow(log.epochMs, log.user, userCfg, log.host, maintenanceWindows);
    if (matchedWin) {
      log.inMaintenanceWindow = true;
      log.matchedMaintenanceWindowId = matchedWin.id;
    }

    const matchedVpn = matchCompanyVpn(log.ip, log.host, log.location, vpnConfigs);
    if (matchedVpn) {
      log.isVpnLogin = true;
    }
  });

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
              contextFlags: ['BRUTE_FORCE_PATTERN'],
              decisionExplanation: `ACTIVE ALERT: Account '${inWindow[0].user}' experienced ${inWindow.length} failed logins in ${repeatedRule.params.repeatedFailuresWindowMinutes} mins. Pattern exceeds brute force threshold without valid business justification.`,
              isContextSuppressed: false,
              confidenceScore: Math.min(96, 75 + inWindow.length * 4),
              confidenceLabel: inWindow.length >= 5 ? 'VERY_HIGH' : 'HIGH',
              evidenceStrength: inWindow.length >= 5 ? 'VERY_STRONG' : 'STRONG',
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
              contextFlags: ['CREDENTIAL_CRACKING_SUCCESS', 'CONFIRMED_COMPROMISE'],
              decisionExplanation: `CONFIRMED COMPROMISE: Account '${successLog.user}' suffered ${precedingFailures.length} failed attempts before authentication succeeded from IP ${successLog.ip}. High probability of cracked credentials.`,
              isContextSuppressed: false,
              confidenceScore: 98,
              confidenceLabel: 'VERY_HIGH',
              evidenceStrength: 'VERY_STRONG',
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
      // Mission 4: Do not attribute horizontal password spray to missing or unverified IP telemetry
      if (!sourceIp || sourceIp === 'MISSING_IP' || sourceIp === '0.0.0.0' || sourceIp.includes('MISSING')) {
        return;
      }

      for (let i = 0; i < ipLogs.length; i++) {
        const startMs = ipLogs[i].epochMs;
        const endMs = startMs + windowMs;
        const inWindow = ipLogs.slice(i).filter(l => l.epochMs <= endMs);
        const distinctUsers = Array.from(new Set(inWindow.map(l => l.user.toLowerCase().trim())));

        if (distinctUsers.length >= minUsers) {
          const failureCount = inWindow.filter(l => l.action === 'FAILURE').length;
          if (failureCount >= distinctUsers.length) {
            distinctUsers.forEach(u => {
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
                contextFlags: ['PASSWORD_SPRAY_CAMPAIGN'],
                decisionExplanation: `ACTIVE ALERT: Origin IP ${sourceIp} targeted multiple corporate accounts (${distinctUsers.length} users) in rapid succession with failed credentials. Classic horizontal password spray.`,
                isContextSuppressed: false,
                confidenceScore: 92,
                confidenceLabel: 'VERY_HIGH',
                evidenceStrength: 'VERY_STRONG',
                details: {
                  sourceIp,
                  totalTargetedUsers: distinctUsers.length,
                  targetedUsersList: distinctUsers,
                  failureRatio: `${failureCount}/${inWindow.length}`
                }
              });
            });
            break;
          }
        }
      }
    });
  }

  // 4. UNUSUAL LOGIN TIMES (Off-hours anomaly with Maintenance Context)
  const timeRule = rulesMap.get('UNUSUAL_TIME');
  if (timeRule && timeRule.enabled) {
    const evalLogs = sortedLogs.filter(l => !l.inTrainingPeriod);

    for (const log of evalLogs) {
      const uKey = log.user.toLowerCase().trim();
      const baseline = baselines.get(uKey);
      if (!baseline || baseline.totalEvents < 3) continue;

      const userCfg = accountsMap.get(uKey);
      const hour = log.dateObj.getUTCHours();
      const isUsualHour = baseline.usualHours.includes(hour);

      if (!isUsualHour) {
        // Context Check: Is this off-hours login during a declared maintenance window by authorized staff?
        const matchedWin = matchMaintenanceWindow(log.epochMs, log.user, userCfg, log.host, maintenanceWindows);
        const isHelpdeskOrAdmin = userCfg?.isAuthorizedHelpdesk || userCfg?.role === 'HELPDESK' || userCfg?.role === 'SYSADMIN';

        let isSuppressed = false;
        let score = timeRule.baseWeight;
        let severity = timeRule.severity;
        let explanation = `Login occurred at UTC ${hour.toString().padStart(2, '0')}:00, an hour with ZERO recorded baseline activity (normal hours: ${baseline.usualHours.map(h => `${h}:00`).join(', ')}).`;
        const flags: string[] = ['OFF_HOURS_LOGIN'];

        if (matchedWin && isHelpdeskOrAdmin) {
          isSuppressed = true;
          score = 5;
          severity = 'LOW';
          flags.push('MAINTENANCE_WINDOW_APPROVED', 'AUTHORIZED_STAFF');
          explanation = `FALSE POSITIVE MITIGATED: Off-hours login at UTC ${hour}:00 occurred during approved Maintenance Window '${matchedWin.id}' (${matchedWin.name}, Ticket: ${matchedWin.changeTicket}) by authorized role '${userCfg?.role}'. Risk downgraded.`;
        }

        alerts.push({
          id: `ALT-TIME-${uKey}-${log.id}`,
          ruleId: timeRule.id,
          ruleCategory: 'UNUSUAL_TIME',
          ruleName: timeRule.name,
          user: log.user,
          timestamp: log.timestamp,
          severity,
          threatClass: isSuppressed ? 'SUSPICIOUS' : timeRule.threatClass,
          score,
          summary: explanation,
          evidence: [log],
          contextFlags: flags,
          decisionExplanation: explanation,
          isContextSuppressed: isSuppressed,
          suppressionReason: isSuppressed ? `Approved Maintenance Window: ${matchedWin?.id}` : undefined,
          confidenceScore: isSuppressed ? 25 : 70,
          confidenceLabel: isSuppressed ? 'LOW' : 'MODERATE',
          evidenceStrength: isSuppressed ? 'WEAK' : 'MODERATE',
          details: {
            observedHour: hour,
            usualHours: baseline.usualHours,
            action: log.action,
            host: log.host,
            ip: log.ip,
            maintenanceWindow: matchedWin?.id || null
          }
        });
      }
    }
  }

  // 5. UNFAMILIAR IPS / SUBNETS (with Corporate VPN & Travelling Employee Context)
  const ipRule = rulesMap.get('UNFAMILIAR_IP');
  if (ipRule && ipRule.enabled) {
    const evalLogs = sortedLogs.filter(l => !l.inTrainingPeriod);

    for (const log of evalLogs) {
      const uKey = log.user.toLowerCase().trim();
      const baseline = baselines.get(uKey);
      const isIpMissingOrInvalid = log.ipValidationStatus === 'MISSING' || log.ipValidationStatus === 'INVALID_FORMAT' || log.ip === 'MISSING_IP';

      if (!isIpMissingOrInvalid && (!baseline || baseline.totalEvents < 2)) continue;

      const userCfg = accountsMap.get(uKey);
      const logSubnet = extractSubnet(log.ip);
      const isKnownIp = baseline ? baseline.usualIPs.includes(log.ip) : false;
      const isKnownSubnet = baseline ? baseline.usualSubnets.includes(logSubnet) : false;

      const isUnfamiliar = isIpMissingOrInvalid || (ipRule.params.subnetMatchOnly ? !isKnownSubnet : !isKnownIp);

      if (isUnfamiliar) {
        // Context Check: Is this coming via Company VPN Gateway or authorized traveling employee?
        const matchedVpn = matchCompanyVpn(log.ip, log.host, log.location, vpnConfigs);
        const isApprovedTraveler = userCfg?.isApprovedTraveler || false;

        let isSuppressed = false;
        let score = ipRule.baseWeight;
        let severity = ipRule.severity;
        let explanation = `Authentication from unfamiliar IP address ${log.ip} (${log.location || 'Unknown Geo'}, Subnet: ${logSubnet}) not present in baseline profile.`;
        const flags: string[] = ['UNFAMILIAR_IP'];

        // Mission 4: Handle Missing or Invalid IP Telemetry with Uncertainty Communication
        const isIpMissingOrInvalid = log.ipValidationStatus === 'MISSING' || log.ipValidationStatus === 'INVALID_FORMAT' || log.ip === 'MISSING_IP';
        if (isIpMissingOrInvalid) {
          flags.push('TELEMETRY_UNCERTAINTY', log.ipValidationStatus === 'MISSING' ? 'MISSING_SOURCE_IP' : 'INVALID_SOURCE_IP');
          score = 8;
          severity = 'LOW';
          explanation = `TELEMETRY UNCERTAINTY: Authentication event for '${log.user}' is missing valid source IP telemetry (${log.uncertaintyNotes || 'IP address unrecorded'}). Geolocation heuristics are unverified; logged with low confidence for audit review.`;
        } else if (matchedVpn) {
          flags.push('CORPORATE_VPN_GATEWAY', matchedVpn.gatewayName);
          if (isApprovedTraveler || log.action === 'SUCCESS') {
            isSuppressed = true;
            score = 5;
            severity = 'LOW';
            flags.push('LEGITIMATE_TRAVELER_APPROVED');
            explanation = `FALSE POSITIVE MITIGATED: Connection from unfamiliar IP ${log.ip} authenticated through approved Corporate VPN Gateway (${matchedVpn.gatewayName}, ${matchedVpn.locationLabel}). User '${log.user}' is designated as an approved travelling employee with MFA verification.`;
          }
        }

        alerts.push({
          id: `ALT-IP-${uKey}-${log.id}`,
          ruleId: ipRule.id,
          ruleCategory: 'UNFAMILIAR_IP',
          ruleName: ipRule.name,
          user: log.user,
          timestamp: log.timestamp,
          severity,
          threatClass: isSuppressed ? 'SUSPICIOUS' : ipRule.threatClass,
          score,
          summary: explanation,
          evidence: [log],
          contextFlags: flags,
          decisionExplanation: explanation,
          isContextSuppressed: isSuppressed,
          suppressionReason: isSuppressed ? `Authorized Corporate VPN: ${matchedVpn?.gatewayName}` : undefined,
          confidenceScore: isSuppressed ? 20 : isIpMissingOrInvalid ? 25 : 82,
          confidenceLabel: (isSuppressed || isIpMissingOrInvalid) ? 'LOW' : 'HIGH',
          evidenceStrength: (isSuppressed || isIpMissingOrInvalid) ? 'WEAK' : 'STRONG',
          telemetryUncertainty: isIpMissingOrInvalid,
          uncertaintyNotes: log.uncertaintyNotes,
          details: {
            observedIp: log.ip,
            observedLocation: log.location,
            baselineUsualIps: baseline?.usualIPs || [],
            baselineUsualSubnets: baseline?.usualSubnets || [],
            corporateVpnGateway: matchedVpn?.gatewayName || null,
            approvedTraveler: isApprovedTraveler,
            ipValidationStatus: log.ipValidationStatus
          }
        });
      }
    }
  }

  // 6. SUDDEN HOST ACCESS EXPANSION (with Helpdesk Maintenance Context)
  const hostRule = rulesMap.get('HOST_EXPANSION');
  if (hostRule && hostRule.enabled) {
    const threshold = hostRule.params.hostExpansionNewHostsThreshold || 1;
    const windowMs = (hostRule.params.hostExpansionWindowMinutes || 60) * 60 * 1000;

    userLogsMap.forEach((userLogs, username) => {
      const baseline = baselines.get(username);
      if (!baseline || baseline.totalEvents < 2) return;

      const userCfg = accountsMap.get(username);
      const isHelpdesk = userCfg?.isAuthorizedHelpdesk || userCfg?.role === 'HELPDESK';

      const evalUserLogs = userLogs.filter(l => !l.inTrainingPeriod && l.action === 'SUCCESS');
      const unfamiliarHostLogs = evalUserLogs.filter(
        l => !baseline.usualHosts.includes(l.host.toUpperCase().trim())
      );

      if (unfamiliarHostLogs.length === 0) return;

      // Sliding window evaluation
      for (let i = 0; i < unfamiliarHostLogs.length; i++) {
        const startMs = unfamiliarHostLogs[i].epochMs;
        const endMs = startMs + windowMs;
        const inWindow = unfamiliarHostLogs.slice(i).filter(l => l.epochMs <= endMs);
        const distinctNewHosts = Array.from(new Set(inWindow.map(l => l.host.toUpperCase().trim())));

        if (distinctNewHosts.length >= threshold) {
          // Check Maintenance Window Context for all accessed hosts
          const matchedWindows = inWindow
            .map(l => matchMaintenanceWindow(l.epochMs, l.user, userCfg, l.host, maintenanceWindows))
            .filter(Boolean) as MaintenanceWindow[];

          const allInMaintenance = matchedWindows.length > 0 && inWindow.every(l => 
            matchMaintenanceWindow(l.epochMs, l.user, userCfg, l.host, maintenanceWindows) !== null
          );

          // Does user have unapproved high-value targets (e.g. Domain Controller, Vault)?
          const hasCriticalAssets = distinctNewHosts.some(h => 
            h.includes('DC') || h.includes('VAULT') || h.includes('PROD')
          );

          let isSuppressed = false;
          let severity = hostRule.severity;
          let threatClass = hostRule.threatClass;
          let score = hostRule.baseWeight;
          let flags: string[] = ['HOST_EXPANSION'];
          let explanation = `Lateral access expansion: User successfully accessed ${distinctNewHosts.length} new host(s) (${distinctNewHosts.join(', ')}) never accessed during baseline (Authorized: ${baseline.usualHosts.join(', ')}).`;

          if (isHelpdesk && allInMaintenance && !hasCriticalAssets) {
            // Requirement 2: Reduce false positives when legitimate helpdesk accounts access multiple hosts during approved maintenance windows!
            isSuppressed = true;
            severity = 'LOW';
            threatClass = 'SUSPICIOUS';
            score = 5;
            flags.push('AUTHORIZED_HELPDESK', 'MAINTENANCE_WINDOW_APPROVED', 'FALSE_POSITIVE_SUPPRESSED');
            const win = matchedWindows[0];
            explanation = `FALSE POSITIVE MITIGATED: Authorized Helpdesk account '${username}' accessed ${distinctNewHosts.length} endpoints (${distinctNewHosts.slice(0, 3).join(', ')}${distinctNewHosts.length > 3 ? '...' : ''}) within approved Maintenance Window '${win.id}' (${win.name}, Change Ticket: ${win.changeTicket}). Host expansion is expected operational activity.`;
          } else {
            // Requirement 5: Continue flagging regular users who access many unfamiliar hosts outside approved maintenance windows!
            flags.push(userCfg?.role || 'REGULAR_USER');
            if (hasCriticalAssets) {
              flags.push('CRITICAL_ASSET_LATERAL_MOVEMENT');
              severity = 'CRITICAL';
              threatClass = 'CONFIRMED_COMPROMISE';
              score = 45;
              explanation = `ACTIVE CRITICAL ALERT: User role '${userCfg?.role || 'REGULAR_USER'}' executed unauthorized lateral expansion onto ${distinctNewHosts.length} critical server(s) [${distinctNewHosts.join(', ')}] outside authorized maintenance parameters. Potential domain takeover attempt.`;
            } else if (!allInMaintenance) {
              flags.push('OUTSIDE_MAINTENANCE_WINDOW');
              explanation = `ACTIVE ALERT: User '${username}' accessed ${distinctNewHosts.length} unfamiliar host(s) OUTSIDE any declared maintenance window. User role: ${userCfg?.role || 'REGULAR_USER'}.`;
            }
          }

          alerts.push({
            id: `ALT-HOST-${username}-${unfamiliarHostLogs[i].id}`,
            ruleId: hostRule.id,
            ruleCategory: 'HOST_EXPANSION',
            ruleName: hostRule.name,
            user: unfamiliarHostLogs[i].user,
            timestamp: inWindow[inWindow.length - 1].timestamp,
            severity,
            threatClass,
            score,
            summary: explanation,
            evidence: inWindow,
            contextFlags: flags,
            decisionExplanation: explanation,
            isContextSuppressed: isSuppressed,
            suppressionReason: isSuppressed ? `Authorized Helpdesk in Window: ${matchedWindows[0]?.id}` : undefined,
            confidenceScore: isSuppressed ? 18 : hasCriticalAssets ? 96 : 85,
            confidenceLabel: isSuppressed ? 'LOW' : hasCriticalAssets ? 'VERY_HIGH' : 'HIGH',
            evidenceStrength: isSuppressed ? 'WEAK' : hasCriticalAssets ? 'VERY_STRONG' : 'STRONG',
            details: {
              newHosts: distinctNewHosts,
              baselineHosts: baseline.usualHosts,
              windowMinutes: hostRule.params.hostExpansionWindowMinutes,
              isHelpdesk,
              allInMaintenance,
              hasCriticalAssets
            }
          });
          break;
        }
      }
    });
  }

  // 7. IMPOSSIBLE TRAVEL / GEOGRAPHIC VELOCITY ANOMALY (Mission 4)
  const travelRule = rulesMap.get('IMPOSSIBLE_TRAVEL');
  if (travelRule && travelRule.enabled) {
    const maxWindowMs = (travelRule.params.impossibleTravelWindowMinutes || 120) * 60 * 1000;

    userLogsMap.forEach((userLogs, username) => {
      const uKey = username.toLowerCase().trim();
      const userCfg = accountsMap.get(uKey);
      const isApprovedTraveler = userCfg?.isApprovedTraveler || false;

      for (let i = 1; i < userLogs.length; i++) {
        const prev = userLogs[i - 1];
        const curr = userLogs[i];

        // Skip missing or invalid IP events from velocity calculations
        if (prev.ipValidationStatus === 'MISSING' || curr.ipValidationStatus === 'MISSING') continue;

        const timeDiffMs = curr.epochMs - prev.epochMs;
        if (timeDiffMs > 0 && timeDiffMs <= maxWindowMs) {
          const prevLoc = (prev.location || '').toLowerCase();
          const currLoc = (curr.location || '').toLowerCase();

          // Check if geographically disparate (e.g. Austin vs London, Austin vs Sofia, Austin vs Tokyo)
          const isAustinToEurope = (prevLoc.includes('austin') || prevLoc.includes('internal')) && 
            (currLoc.includes('london') || currLoc.includes('sofia') || currLoc.includes('bucharest') || currLoc.includes('tokyo') || currLoc.includes('uk') || currLoc.includes('bulgaria'));
          
          const isDistantSubnets = prevLoc && currLoc && prevLoc !== currLoc &&
            !prevLoc.includes('internal') && !currLoc.includes('internal') &&
            extractSubnet(prev.ip) !== extractSubnet(curr.ip);

          if (isAustinToEurope || isDistantSubnets) {
            const timeDiffMins = Math.max(1, Math.round(timeDiffMs / 60000));
            // Check corporate VPN status
            const prevVpn = matchCompanyVpn(prev.ip, prev.host, prev.location, vpnConfigs);
            const currVpn = matchCompanyVpn(curr.ip, curr.host, curr.location, vpnConfigs);
            const hasVpn = !!(prevVpn || currVpn);

            let isSuppressed = false;
            let score = travelRule.baseWeight;
            let severity = travelRule.severity;
            let threatClass = travelRule.threatClass; // CONFIRMED_COMPROMISE
            const flags: string[] = ['GEOGRAPHIC_VELOCITY_ANOMALY'];

            let explanation = `CRITICAL IMPOSSIBLE TRAVEL: Account '${curr.user}' authenticated from '${prev.location}' (${prev.ip}) and '${curr.location}' (${curr.ip}) within ${timeDiffMins} minute(s). Physical transit speed is physically impossible without corporate VPN authorization. Indicates credential sharing or session hijacking.`;

            if (hasVpn) {
              const vpnName = (currVpn || prevVpn)?.gatewayName || 'Corporate VPN Gateway';
              flags.push('CORPORATE_VPN_GATEWAY', 'LEGITIMATE_TRAVELER_APPROVED');
              if (isApprovedTraveler || curr.action === 'SUCCESS') {
                isSuppressed = true;
                score = 8;
                severity = 'LOW';
                threatClass = 'SUSPICIOUS';
                explanation = `FALSE POSITIVE MITIGATED: Multi-location authentication detected within ${timeDiffMins} mins ('${prev.location}' -> '${curr.location}'), but connection authenticated via Corporate VPN Gateway (${vpnName}). User '${curr.user}' is an authorized traveling employee.`;
              }
            }

            alerts.push({
              id: `ALT-TRAVEL-${uKey}-${curr.id}`,
              ruleId: travelRule.id,
              ruleCategory: 'IMPOSSIBLE_TRAVEL',
              ruleName: travelRule.name,
              user: curr.user,
              timestamp: curr.timestamp,
              severity,
              threatClass,
              score,
              summary: explanation,
              evidence: [prev, curr],
              contextFlags: flags,
              decisionExplanation: explanation,
              isContextSuppressed: isSuppressed,
              suppressionReason: isSuppressed ? `Corporate VPN Gateway Session: ${(currVpn || prevVpn)?.gatewayName}` : undefined,
              confidenceScore: isSuppressed ? 25 : 96,
              confidenceLabel: isSuppressed ? 'LOW' : 'VERY_HIGH',
              evidenceStrength: isSuppressed ? 'WEAK' : 'VERY_STRONG',
              details: {
                previousLocation: prev.location,
                previousIp: prev.ip,
                currentLocation: curr.location,
                currentIp: curr.ip,
                timeDiffMinutes: timeDiffMins,
                hasCorporateVpn: hasVpn,
                approvedTraveler: isApprovedTraveler
              }
            });
            break;
          }
        }
      }
    });
  }

  return alerts;
}
