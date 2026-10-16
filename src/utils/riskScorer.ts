import { DetectionAlert, UserIncident, SeverityLevel, ThreatClass, RuleCategory, NormalizedAuthLog } from '../types';

export function calculateRiskScore(alerts: DetectionAlert[]): {
  score: number;
  severity: SeverityLevel;
  threatClass: ThreatClass;
} {
  if (alerts.length === 0) {
    return { score: 0, severity: 'LOW', threatClass: 'SUSPICIOUS' };
  }

  // Check if any alert is marked as CONFIRMED_COMPROMISE
  const hasConfirmedCompromise = alerts.some(a => a.threatClass === 'CONFIRMED_COMPROMISE');

  // Sum up base weights with diminishing returns for duplicates
  const categoryWeights: Record<RuleCategory, number> = {
    BURST_FAILURE_THEN_SUCCESS: 45,
    HOST_EXPANSION: 30,
    PASSWORD_SPRAY: 25,
    REPEATED_FAILURES: 20,
    UNFAMILIAR_IP: 18,
    UNUSUAL_TIME: 15
  };

  const triggeredCategories = new Set(alerts.map(a => a.ruleCategory));
  let totalScore = 0;

  // Add category weight
  triggeredCategories.forEach(cat => {
    totalScore += categoryWeights[cat] || 15;
  });

  // Compounding multiplier: If multiple distinct attack patterns are observed together,
  // the probability of an active intrusion escalates drastically.
  const distinctCategoriesCount = triggeredCategories.size;
  if (distinctCategoriesCount >= 3) {
    totalScore *= 1.35;
  } else if (distinctCategoriesCount >= 2) {
    totalScore *= 1.15;
  }

  // Volume factor based on total evidence rows
  const totalEvidenceCount = alerts.reduce((acc, a) => acc + (a.evidence?.length || 1), 0);
  if (totalEvidenceCount > 10) {
    totalScore += 10;
  } else if (totalEvidenceCount > 5) {
    totalScore += 5;
  }

  // Cap between 0 and 100
  let finalScore = Math.min(100, Math.round(totalScore));

  // If confirmed compromise, floor at 85
  if (hasConfirmedCompromise && finalScore < 85) {
    finalScore = 85;
  }

  // Severity classification
  let severity: SeverityLevel = 'LOW';
  if (finalScore >= 80) {
    severity = 'CRITICAL';
  } else if (finalScore >= 60) {
    severity = 'HIGH';
  } else if (finalScore >= 35) {
    severity = 'MEDIUM';
  } else {
    severity = 'LOW';
  }

  // Threat classification
  let threatClass: ThreatClass = 'SUSPICIOUS';
  if (hasConfirmedCompromise || (finalScore >= 80 && triggeredCategories.has('HOST_EXPANSION'))) {
    threatClass = 'CONFIRMED_COMPROMISE';
  }

  return { score: finalScore, severity, threatClass };
}

export function generateTriageSteps(
  user: string,
  categories: RuleCategory[],
  hosts: string[],
  ips: string[],
  threatClass: ThreatClass
): string[] {
  const steps: string[] = [];

  if (threatClass === 'CONFIRMED_COMPROMISE') {
    steps.push(`🚨 CRITICAL: Immediately revoke all active Kerberos TGTs, OAuth/SAML sessions, and refresh tokens for user '${user}'.`);
    steps.push(`Force an administrative credential reset and invalidate current MFA registrations.`);
  } else {
    steps.push(`Contact user '${user}' via verified out-of-band communication (phone/Slack) to confirm whether these login attempts were authorized.`);
  }

  if (categories.includes('BURST_FAILURE_THEN_SUCCESS')) {
    steps.push(`Investigate the successful authentication event: check IP geodistance, user agent anomalies, and whether MFA challenge was bypassed or fatigued.`);
  }

  if (categories.includes('REPEATED_FAILURES') || categories.includes('PASSWORD_SPRAY')) {
    if (ips.length > 0) {
      steps.push(`Add perimeter firewall / WAF temporary drop rule for origin IP(s): ${ips.slice(0, 3).join(', ')}.`);
    }
    steps.push(`Review directory service event logs (Event ID 4625/4740) to determine if account is locked out or targeted across domain controllers.`);
  }

  if (categories.includes('HOST_EXPANSION')) {
    const criticalHosts = hosts.slice(0, 3).join(', ');
    steps.push(`Isolate endpoint(s) [${criticalHosts}] from the corporate network to prevent lateral movement propagation.`);
    steps.push(`Inspect Endpoint Detection & Response (EDR) telemetry on [${criticalHosts}] for spawned processes (PowerShell, cmd.exe, wmic, rundll32) and new persistence artifacts.`);
  }

  if (categories.includes('UNFAMILIAR_IP') || categories.includes('UNUSUAL_TIME')) {
    steps.push(`Check VPN and conditional access logs for impossible travel or concurrent active sessions from conflicting geographic regions.`);
  }

  steps.push(`Document all findings in the SOC incident management ticketing system and notify the Incident Response Commander if lateral spread is verified.`);

  return steps;
}
