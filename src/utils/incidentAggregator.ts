import { DetectionAlert, UserIncident, NormalizedAuthLog, RuleCategory, UserAccountConfig } from '../types';
import { calculateRiskScore, generateTriageSteps } from './riskScorer';

export function aggregateIncidents(
  alerts: DetectionAlert[],
  companyId: string = 'COMP-001',
  userAccounts: UserAccountConfig[] = []
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
    const { score, severity, threatClass, isAllContextSuppressed, decisionExplanation } = calculateRiskScore(userAlerts);

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
      updatedAt: new Date().toISOString()
    };

    incidents.push(incident);
  });

  // Sort: Active threats first (highest risk), then benign maintenance at bottom
  return incidents.sort((a, b) => b.riskScore - a.riskScore);
}
