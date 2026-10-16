import { 
  DetectionAlert, 
  UserIncident, 
  NormalizedAuthLog, 
  RuleCategory, 
  UserAccountConfig, 
  UserBaseline, 
  UserHostGraph, 
  GraphNode, 
  GraphEdge, 
  IncidentTimelineEvent 
} from '../types';
import { calculateRiskScore, generateTriageSteps } from './riskScorer';

export function aggregateIncidents(
  alerts: DetectionAlert[],
  companyId: string = 'COMP-001',
  userAccounts: UserAccountConfig[] = [],
  baselines: Map<string, UserBaseline> = new Map()
): UserIncident[] {
  const userAlertsMap = new Map<string, DetectionAlert[]>();
  const accountsMap = new Map<string, UserAccountConfig>();
  userAccounts.forEach(acc => accountsMap.set(acc.username.toLowerCase(), acc));

  // Group alerts by user
  for (const alert of alerts) {
    const userKey = alert.user.toLowerCase().trim();
    if (!userAlertsMap.has(userKey)) {
      userAlertsMap.set(userKey, []);
    }
    userAlertsMap.get(userKey)!.push(alert);
  }

  const incidents: UserIncident[] = [];

  userAlertsMap.forEach((userAlerts, userKey) => {
    const userCfg = accountsMap.get(userKey);
    const baseline = baselines.get(userKey);
    const { score, severity, threatClass, isAllContextSuppressed, decisionExplanation, riskBreakdown } = calculateRiskScore(userAlerts);

    // Collect all evidence rows
    const evidenceMap = new Map<string, NormalizedAuthLog>();
    userAlerts.forEach(a => {
      a.evidence.forEach(ev => {
        evidenceMap.set(ev.id, ev);
      });
    });

    const evidenceRows = Array.from(evidenceMap.values()).sort((a, b) => a.epochMs - b.epochMs);
    const triggeredCategories = Array.from(new Set(userAlerts.map(a => a.ruleCategory))) as RuleCategory[];

    const involvedHosts = Array.from(
      new Set(evidenceRows.map(e => e.host.toUpperCase().trim()).filter(Boolean))
    );
    const involvedIPs = Array.from(
      new Set(evidenceRows.map(e => e.ip.trim()).filter(Boolean))
    );

    const firstSeen = evidenceRows[0]?.timestamp || userAlerts[0]?.timestamp || new Date().toISOString();
    const lastSeen = evidenceRows[evidenceRows.length - 1]?.timestamp || userAlerts[userAlerts.length - 1]?.timestamp || new Date().toISOString();

    const displayUser = userAlerts[0]?.user || userKey;
    const recommendedTriageSteps = generateTriageSteps(
      displayUser,
      triggeredCategories,
      involvedHosts,
      involvedIPs,
      threatClass,
      isAllContextSuppressed
    );

    // Collect all context flags
    const contextFlagsSet = new Set<string>();
    if (userCfg?.role) contextFlagsSet.add(`ROLE:${userCfg.role}`);
    if (userCfg?.isAuthorizedHelpdesk) contextFlagsSet.add('AUTHORIZED_HELPDESK');
    if (userCfg?.isApprovedTraveler) contextFlagsSet.add('APPROVED_TRAVELER');
    userAlerts.forEach(a => {
      a.contextFlags?.forEach(f => contextFlagsSet.add(f));
    });

    // ==========================================
    // 1. Build Chronological Incident Timeline
    // ==========================================
    const authTimelineEvents: IncidentTimelineEvent[] = evidenceRows.map(ev => ({
      id: `TLE-EVT-${ev.id}`,
      timestamp: ev.timestamp,
      epochMs: ev.epochMs,
      type: ev.action === 'SUCCESS' ? 'AUTH_SUCCESS' : 'AUTH_FAILURE',
      title: ev.action === 'SUCCESS' ? `Successful Login to ${ev.host}` : `Failed Authentication on ${ev.host}`,
      description: `${ev.action} authentication attempt from origin IP ${ev.ip} (${ev.location || 'Unknown Location'}). Reason: ${ev.failureReason || (ev.action === 'SUCCESS' ? 'Logon successful' : 'Authentication failure')}`,
      ip: ev.ip,
      host: ev.host,
      severity: ev.action === 'FAILURE' ? 'HIGH' : 'LOW',
      isSuspicious: ev.action === 'FAILURE' || (baseline ? !baseline.usualHosts.includes(ev.host) : false),
      failureReason: ev.failureReason,
      location: ev.location
    }));

    const alertTimelineEvents: IncidentTimelineEvent[] = userAlerts.map(alt => {
      const alertEpoch = new Date(alt.timestamp).getTime();
      return {
        id: `TLE-ALT-${alt.id}`,
        timestamp: alt.timestamp,
        epochMs: isNaN(alertEpoch) ? Date.now() : alertEpoch,
        type: 'DETECTION_ALERT',
        title: `Triggered Rule: ${alt.ruleName}`,
        description: alt.summary,
        severity: alt.severity,
        alertId: alt.id,
        ruleCategory: alt.ruleCategory,
        confidence: alt.confidenceLabel || 'HIGH',
        isSuspicious: true
      };
    });

    const timelineEvents = [...authTimelineEvents, ...alertTimelineEvents].sort((a, b) => {
      if (a.epochMs !== b.epochMs) return a.epochMs - b.epochMs;
      if (a.type !== 'DETECTION_ALERT' && b.type === 'DETECTION_ALERT') return -1;
      if (a.type === 'DETECTION_ALERT' && b.type !== 'DETECTION_ALERT') return 1;
      return 0;
    });

    // ==========================================
    // 2. Build User-to-Host Communication Graph
    // ==========================================
    const totalUserFails = evidenceRows.filter(e => e.action === 'FAILURE').length;
    const totalUserSuccesses = evidenceRows.filter(e => e.action === 'SUCCESS').length;

    const graphNodes: GraphNode[] = [];
    const graphEdges: GraphEdge[] = [];

    // Central User Node
    graphNodes.push({
      id: `user:${displayUser}`,
      label: displayUser,
      type: 'USER',
      failCount: totalUserFails,
      successCount: totalUserSuccesses,
      details: {
        role: userCfg?.role || 'REGULAR_USER',
        isHelpdesk: userCfg?.isAuthorizedHelpdesk,
        isTraveler: userCfg?.isApprovedTraveler
      }
    });

    // IP Nodes & User -> IP Edges
    involvedIPs.forEach(ip => {
      const ipEvents = evidenceRows.filter(e => e.ip === ip);
      const ipFails = ipEvents.filter(e => e.action === 'FAILURE').length;
      const ipSuccesses = ipEvents.filter(e => e.action === 'SUCCESS').length;
      const isVpn = ip.startsWith('10.250.') || ip.startsWith('172.20.') || ipEvents.some(e => e.location?.toLowerCase().includes('vpn'));

      graphNodes.push({
        id: `ip:${ip}`,
        label: ip,
        type: 'IP',
        isVpn,
        failCount: ipFails,
        successCount: ipSuccesses,
        details: {
          location: ipEvents[0]?.location || 'Internal / Direct',
          isVpn
        }
      });

      graphEdges.push({
        id: `edge:user->${ip}`,
        source: `user:${displayUser}`,
        target: `ip:${ip}`,
        action: ipFails > 0 && ipSuccesses > 0 ? 'MIXED' : ipFails > 0 ? 'FAILURE' : 'SUCCESS',
        count: ipEvents.length
      });
    });

    // Host Nodes & IP -> Host Edges
    let novelHostsCount = 0;
    let baselineHostsCount = 0;

    involvedHosts.forEach(host => {
      const hostEvents = evidenceRows.filter(e => e.host.toUpperCase() === host);
      const hostFails = hostEvents.filter(e => e.action === 'FAILURE').length;
      const hostSuccesses = hostEvents.filter(e => e.action === 'SUCCESS').length;

      const isBaseline = baseline ? baseline.usualHosts.includes(host) : false;
      if (isBaseline) {
        baselineHostsCount++;
      } else {
        novelHostsCount++;
      }

      const isCritical = host.includes('DC') || host.includes('VAULT') || host.includes('PROD') || host.includes('SRV');

      graphNodes.push({
        id: `host:${host}`,
        label: host,
        type: 'HOST',
        isBaseline,
        isNovel: !isBaseline,
        isCritical,
        failCount: hostFails,
        successCount: hostSuccesses,
        details: {
          novelty: isBaseline ? 'Baseline Habitual Host' : 'Novel / Unfamiliar Host',
          isCriticalTier0: isCritical
        }
      });

      // Find which IPs communicated with this host
      const connectedIps = Array.from(new Set(hostEvents.map(e => e.ip)));
      connectedIps.forEach(ip => {
        const pathEvents = hostEvents.filter(e => e.ip === ip);
        const pathFails = pathEvents.filter(e => e.action === 'FAILURE').length;
        const pathSuccesses = pathEvents.filter(e => e.action === 'SUCCESS').length;

        graphEdges.push({
          id: `edge:${ip}->${host}`,
          source: `ip:${ip}`,
          target: `host:${host}`,
          action: pathFails > 0 && pathSuccesses > 0 ? 'MIXED' : pathFails > 0 ? 'FAILURE' : 'SUCCESS',
          count: pathEvents.length,
          isNovelPath: !isBaseline
        });
      });
    });

    const hostGraph: UserHostGraph = {
      user: displayUser,
      nodes: graphNodes,
      edges: graphEdges,
      totalHostsAccessed: involvedHosts.length,
      novelHostsCount,
      baselineHostsCount
    };

    const incident: UserIncident = {
      id: `INC-${userKey.toUpperCase()}-${Math.abs(score * 31 + userAlerts.length).toString(16).toUpperCase()}`,
      companyId,
      user: displayUser,
      riskScore: score,
      severity,
      threatClass,
      status: isAllContextSuppressed ? 'BENIGN_MAINTENANCE' : 'NEW',
      alerts: userAlerts,
      triggeredRuleCategories: triggeredCategories,
      evidenceRows,
      evidenceCount: evidenceRows.length,
      firstSeen,
      lastSeen,
      involvedHosts,
      involvedIPs,
      recommendedTriageSteps,
      accountRole: userCfg?.role || 'REGULAR_USER',
      isHelpdesk: userCfg?.isAuthorizedHelpdesk || userCfg?.role === 'HELPDESK',
      isTravelingEmployee: userCfg?.isApprovedTraveler,
      contextFlags: Array.from(contextFlagsSet),
      decisionExplanation,
      isContextSuppressed: isAllContextSuppressed,
      notes: [
        {
          id: `NOTE-${Date.now()}-1`,
          author: 'AegisSOC Context Triage Engine',
          timestamp: new Date().toISOString(),
          text: isAllContextSuppressed
            ? `Context evaluation: User '${displayUser}' activity verified against declared maintenance window & authorized corporate VPN. Risk score reduced to ${score}/100 to prevent false-positive alert fatigue.`
            : `Incident evaluated with risk score ${score}/100. ${decisionExplanation}`
        }
      ],
      updatedAt: new Date().toISOString(),
      riskBreakdown,
      hostGraph,
      timelineEvents
    };

    incidents.push(incident);
  });

  // Sort: Active threats first (highest risk), then benign maintenance at bottom
  return incidents.sort((a, b) => b.riskScore - a.riskScore);
}
