import { DetectionAlert, UserIncident, NormalizedAuthLog, RuleCategory } from '../types';
import { calculateRiskScore, generateTriageSteps } from './riskScorer';

export function aggregateIncidents(
  alerts: DetectionAlert[],
  companyId: string = 'COMP-001'
): UserIncident[] {
  const userAlertsMap = new Map<string, DetectionAlert[]>();

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
    const { score, severity, threatClass } = calculateRiskScore(userAlerts);

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
      threatClass
    );

    const incident: UserIncident = {
      id: `INC-${userKey.toUpperCase()}-${Math.abs(score * 31 + userAlerts.length).toString(16).toUpperCase()}`,
      companyId,
      user: displayUser,
      riskScore: score,
      severity,
      threatClass,
      status: 'NEW',
      alerts: userAlerts,
      triggeredRuleCategories: triggeredCategories,
      evidenceRows,
      evidenceCount: evidenceRows.length,
      firstSeen,
      lastSeen,
      involvedHosts,
      involvedIPs,
      recommendedTriageSteps,
      notes: [
        {
          id: `NOTE-${Date.now()}-1`,
          author: 'AegisSOC Automated Triage',
          timestamp: new Date().toISOString(),
          text: `Incident generated automatically with risk score ${score}/100. ${userAlerts.length} correlated alert(s) across ${triggeredCategories.length} rule categories.`
        }
      ],
      updatedAt: new Date().toISOString()
    };

    incidents.push(incident);
  });

  // Sort incidents by risk score descending (highest risk first)
  return incidents.sort((a, b) => b.riskScore - a.riskScore);
}
