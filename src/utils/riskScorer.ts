import { DetectionAlert, SeverityLevel, ThreatClass, RuleCategory, RiskScoreContribution } from '../types';

export interface CalculatedRiskResult {
  score: number;
  severity: SeverityLevel;
  threatClass: ThreatClass;
  isAllContextSuppressed: boolean;
  decisionExplanation: string;
  riskBreakdown: RiskScoreContribution[];
}

export function calculateRiskScore(alerts: DetectionAlert[]): CalculatedRiskResult {
  if (alerts.length === 0) {
    return { 
      score: 0, 
      severity: 'LOW', 
      threatClass: 'SUSPICIOUS',
      isAllContextSuppressed: false,
      decisionExplanation: 'No anomalies detected.',
      riskBreakdown: []
    };
  }

  // Filter between actionable alerts and context-suppressed alerts
  const actionableAlerts = alerts.filter(a => !a.isContextSuppressed);
  const suppressedAlerts = alerts.filter(a => a.isContextSuppressed);
  const isAllContextSuppressed = actionableAlerts.length === 0 && suppressedAlerts.length > 0;

  const categoryNames: Record<RuleCategory, string> = {
    BURST_FAILURE_THEN_SUCCESS: 'Burst Failure Followed by Success',
    HOST_EXPANSION: 'Sudden Host Access Expansion',
    PASSWORD_SPRAY: 'Horizontal Password Spraying',
    REPEATED_FAILURES: 'Repeated Authentication Failures',
    UNFAMILIAR_IP: 'Unfamiliar IP / Subnet Login',
    UNUSUAL_TIME: 'Unusual / Off-Hours Activity',
    IMPOSSIBLE_TRAVEL: 'Impossible Travel / Geographic Velocity Anomaly'
  };

  const categoryWeights: Record<RuleCategory, number> = {
    BURST_FAILURE_THEN_SUCCESS: 45,
    IMPOSSIBLE_TRAVEL: 40,
    HOST_EXPANSION: 30,
    PASSWORD_SPRAY: 25,
    REPEATED_FAILURES: 20,
    UNFAMILIAR_IP: 18,
    UNUSUAL_TIME: 15
  };

  if (isAllContextSuppressed) {
    const reasons = Array.from(new Set(suppressedAlerts.map(a => a.suppressionReason).filter(Boolean)));
    const breakdown: RiskScoreContribution[] = [];

    // Show benign baseline
    suppressedAlerts.forEach(a => {
      breakdown.push({
        ruleId: a.ruleCategory,
        ruleName: categoryNames[a.ruleCategory] || a.ruleName,
        category: a.ruleCategory,
        pointsAdded: categoryWeights[a.ruleCategory] || 15,
        percentageOfTotal: 100,
        reason: `Anomaly detected during approved operational window`,
        evidenceCount: a.evidence?.length || 1
      });
    });

    const totalRaw = breakdown.reduce((sum, b) => sum + b.pointsAdded, 0);
    const mitigationDiscount = -(totalRaw - 8);

    breakdown.push({
      ruleId: 'CONTEXT_MITIGATION',
      ruleName: 'Operational Context Suppression',
      category: 'UNUSUAL_TIME',
      pointsAdded: mitigationDiscount,
      percentageOfTotal: 0,
      reason: `Mitigated by approved maintenance window / corporate VPN (${reasons.join(', ') || 'Authorized schedule'})`,
      evidenceCount: suppressedAlerts.length
    });

    return {
      score: 8,
      severity: 'LOW',
      threatClass: 'SUSPICIOUS',
      isAllContextSuppressed: true,
      decisionExplanation: `BENIGN CONTEXT MITIGATION: All detected anomalies (${suppressedAlerts.length} events) were verified against approved operational schedules and corporate VPN gateways (${reasons.join(', ')}). Threat risk suppressed to prevent false positive alert fatigue.`,
      riskBreakdown: breakdown
    };
  }

  // Check if any actionable alert is marked as CONFIRMED_COMPROMISE
  const hasConfirmedCompromise = actionableAlerts.some(a => a.threatClass === 'CONFIRMED_COMPROMISE');

  const triggeredCategories = new Set(actionableAlerts.map(a => a.ruleCategory));
  const breakdown: RiskScoreContribution[] = [];
  let rawScore = 0;

  // Add category weight for actionable alerts
  triggeredCategories.forEach(cat => {
    const alertsForCat = actionableAlerts.filter(a => a.ruleCategory === cat);
    const basePts = categoryWeights[cat] || 15;
    const evCount = alertsForCat.reduce((sum, a) => sum + (a.evidence?.length || 1), 0);
    rawScore += basePts;

    breakdown.push({
      ruleId: cat,
      ruleName: categoryNames[cat] || cat,
      category: cat,
      pointsAdded: basePts,
      percentageOfTotal: 0, // computed below
      reason: `Triggered ${alertsForCat.length} alert(s) across ${evCount} suspicious events`,
      evidenceCount: evCount
    });
  });

  // Compounding multiplier for multi-vector attacks
  const distinctCategoriesCount = triggeredCategories.size;
  let multiplierBonus = 0;
  if (distinctCategoriesCount >= 3) {
    multiplierBonus = Math.round(rawScore * 0.35);
    rawScore += multiplierBonus;
    breakdown.push({
      ruleId: 'MULTI_VECTOR_CORRELATION',
      ruleName: 'Multi-Vector Attack Correlation',
      category: 'BURST_FAILURE_THEN_SUCCESS',
      pointsAdded: multiplierBonus,
      percentageOfTotal: 0,
      reason: `Compounding 1.35x multiplier applied for ${distinctCategoriesCount} concurrent anomaly vectors`,
      evidenceCount: distinctCategoriesCount
    });
  } else if (distinctCategoriesCount >= 2) {
    multiplierBonus = Math.round(rawScore * 0.15);
    rawScore += multiplierBonus;
    breakdown.push({
      ruleId: 'MULTI_VECTOR_CORRELATION',
      ruleName: 'Multi-Vector Attack Correlation',
      category: 'BURST_FAILURE_THEN_SUCCESS',
      pointsAdded: multiplierBonus,
      percentageOfTotal: 0,
      reason: `Compounding 1.15x multiplier applied for 2 concurrent anomaly vectors`,
      evidenceCount: distinctCategoriesCount
    });
  }

  // Volume factor based on actionable evidence rows
  const totalEvidenceCount = actionableAlerts.reduce((acc, a) => acc + (a.evidence?.length || 1), 0);
  if (totalEvidenceCount > 10) {
    rawScore += 10;
    breakdown.push({
      ruleId: 'VOLUME_FACTOR',
      ruleName: 'High Anomaly Event Volume',
      category: 'REPEATED_FAILURES',
      pointsAdded: 10,
      percentageOfTotal: 0,
      reason: `High anomaly volume bonus (+10 pts for ${totalEvidenceCount} events)`,
      evidenceCount: totalEvidenceCount
    });
  } else if (totalEvidenceCount > 5) {
    rawScore += 5;
    breakdown.push({
      ruleId: 'VOLUME_FACTOR',
      ruleName: 'Elevated Anomaly Volume',
      category: 'REPEATED_FAILURES',
      pointsAdded: 5,
      percentageOfTotal: 0,
      reason: `Elevated volume bonus (+5 pts for ${totalEvidenceCount} events)`,
      evidenceCount: totalEvidenceCount
    });
  }

  // Cap between 0 and 100
  let finalScore = Math.min(100, Math.round(rawScore));

  // If confirmed compromise, floor at 85
  if (hasConfirmedCompromise && finalScore < 85) {
    const floorDelta = 85 - finalScore;
    finalScore = 85;
    breakdown.push({
      ruleId: 'COMPROMISE_FLOOR',
      ruleName: 'Confirmed Compromise Risk Floor',
      category: 'BURST_FAILURE_THEN_SUCCESS',
      pointsAdded: floorDelta,
      percentageOfTotal: 0,
      reason: `Critical credential breach / domain compromise baseline floor`,
      evidenceCount: 1
    });
  }

  // Compute percentage of total for each breakdown item
  const totalPositivePoints = breakdown.filter(b => b.pointsAdded > 0).reduce((sum, b) => sum + b.pointsAdded, 0);
  breakdown.forEach(item => {
    item.percentageOfTotal = totalPositivePoints > 0 
      ? Math.max(0, Math.round((item.pointsAdded / totalPositivePoints) * 100)) 
      : 0;
  });

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
  if (hasConfirmedCompromise || (finalScore >= 80 && (triggeredCategories.has('HOST_EXPANSION') || triggeredCategories.has('IMPOSSIBLE_TRAVEL')))) {
    threatClass = 'CONFIRMED_COMPROMISE';
  }

  const explanations: string[] = [];
  if (hasConfirmedCompromise) {
    explanations.push('Critical threat: Credential compromise pattern identified.');
  }
  if (triggeredCategories.has('IMPOSSIBLE_TRAVEL')) {
    explanations.push('Critical impossible travel anomaly detected across distant geographic locations.');
  }
  if (triggeredCategories.has('HOST_EXPANSION')) {
    explanations.push('Host expansion outside authorized maintenance window detected.');
  }
  if (suppressedAlerts.length > 0) {
    explanations.push(`(${suppressedAlerts.length} operational maintenance events suppressed).`);
  }

  return { 
    score: finalScore, 
    severity, 
    threatClass,
    isAllContextSuppressed: false,
    decisionExplanation: explanations.join(' ') || 'Elevated risk score due to correlated authentication deviations.',
    riskBreakdown: breakdown
  };
}

export function generateTriageSteps(
  user: string,
  categories: RuleCategory[],
  hosts: string[],
  ips: string[],
  threatClass: ThreatClass,
  isAllContextSuppressed: boolean = false
): string[] {
  const steps: string[] = [];

  if (isAllContextSuppressed) {
    steps.push(`1. Verify change ticket reference and maintenance window schedule with IT Desktop Helpdesk.`);
    steps.push(`2. Confirm automated deployment scripts or remote diagnostics completed successfully on targeted workstations.`);
    steps.push(`3. Review post-maintenance system health checks on modified endpoints [${hosts.slice(0, 3).join(', ')}].`);
    steps.push(`4. Close incident ticket as BENIGN_MAINTENANCE (No hostile activity detected).`);
    return steps;
  }

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
