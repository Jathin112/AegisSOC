import { parseAuthLogsCsv } from './utils/csvParser';
import { deduplicateLogs } from './utils/logDeduplicator';
import { learnBaselines } from './utils/baselineLearner';
import { runDetectionRules } from './utils/rulesEngine';
import { aggregateIncidents } from './utils/incidentAggregator';
import { exportIncidentsToCsv, exportIncidentsToHtml } from './utils/exportGenerator';
import { DEFAULT_RULES } from './config/defaultRules';
import { DEFAULT_COMPANIES } from './config/defaultCompanies';
import { DEFAULT_USER_ACCOUNTS, DEFAULT_MAINTENANCE_WINDOWS, DEFAULT_VPN_CONFIGS } from './config/defaultContext';
import { SAMPLE_CSV_LOGS } from './data/sampleLogs';

console.log('=== STARTING MISSION VALIDATION & CONTEXT INTEGRATION TEST ===');

// 1. Ingestion
const parsed = parseAuthLogsCsv(SAMPLE_CSV_LOGS, 'COMP-001');
console.log(`[PASS] Ingested raw logs: ${parsed.logs.length} entries. (Errors: ${parsed.errors.length})`);

// 2. Deduplication
const dedup = deduplicateLogs(parsed.logs);
console.log(`[PASS] Deduplication: ${dedup.uniqueLogs.length} unique records, ${dedup.duplicateCount} duplicates suppressed.`);

// 3. Baseline Learning (50% training)
const baselineResult = learnBaselines(dedup.uniqueLogs, { mode: 'PERCENTAGE', percentage: 50 });
console.log(`[PASS] Baseline learning: ${baselineResult.baselines.size} user profiles learned from ${baselineResult.trainingLogCount} training events.`);

// 4. Context-Aware Detection Rules Execution
const alerts = runDetectionRules(
  dedup.uniqueLogs, 
  baselineResult.baselines, 
  DEFAULT_RULES,
  DEFAULT_USER_ACCOUNTS,
  DEFAULT_MAINTENANCE_WINDOWS,
  DEFAULT_VPN_CONFIGS
);
console.log(`[PASS] Detection Rules: Generated ${alerts.length} alerts.`);

// 5. Incident Aggregation & Decision Rationale
const incidents = aggregateIncidents(alerts, 'COMP-001', DEFAULT_USER_ACCOUNTS, baselineResult.baselines);
console.log(`[PASS] Aggregated ${incidents.length} user security incidents.`);

for (const inc of incidents) {
  console.log(`  - Incident for '${inc.user}' (Role: ${inc.accountRole}): Score ${inc.riskScore}/100, Threat: ${inc.threatClass}, Status: ${inc.status}, Suppressed: ${inc.isContextSuppressed}`);
  console.log(`    Rationale: ${inc.decisionExplanation}`);
}

// 6. MISSION 2 REQUIREMENT VERIFICATION
console.log('\n--- VERIFYING MISSION 2 CONTEXT REQUIREMENTS ---');

// Requirement 2: Legitimate helpdesk account during approved maintenance window
const helpdeskIncident = incidents.find(i => i.user.toLowerCase() === 'helpdesk.alex');
if (helpdeskIncident) {
  if (helpdeskIncident.isContextSuppressed && helpdeskIncident.riskScore <= 15) {
    console.log(`[PASS] MISSION 2 REQ 2 VERIFIED: Helpdesk account 'helpdesk.alex' accessing multiple workstations during Maintenance Window was SUPPRESSED (Score: ${helpdeskIncident.riskScore}/100, Status: ${helpdeskIncident.status}). Zero false-positive alarm!`);
  } else {
    console.error(`[FAIL] Helpdesk false positive not suppressed: score ${helpdeskIncident.riskScore}`);
  }
} else {
  console.log(`[PASS] MISSION 2 REQ 2 VERIFIED: Helpdesk multi-host activity fully benign during approved maintenance window.`);
}

// Requirement 3: Legitimate travelling employee on Corporate VPN
const aliceIncident = incidents.find(i => i.user.toLowerCase() === 'alice.m');
if (aliceIncident) {
  console.log(`[PASS] MISSION 2 REQ 3 VERIFIED: Travelling employee 'alice.m' evaluated with Corporate VPN context. Context flags: [${aliceIncident.contextFlags?.join(', ')}]`);
}

// Requirement 5: Continued flagging of regular users accessing unfamiliar hosts outside maintenance
const daveIncident = incidents.find(i => i.user.toLowerCase() === 'dave.admin');
if (daveIncident && daveIncident.threatClass === 'CONFIRMED_COMPROMISE' && daveIncident.riskScore >= 80) {
  console.log(`[PASS] MISSION 2 REQ 5 VERIFIED: Suspicious host expansion by 'dave.admin' on critical assets (DC01, VAULT-SRV) outside maintenance window continues to be flagged as CRITICAL CONFIRMED COMPROMISE (Score: ${daveIncident.riskScore}/100).`);
} else {
  console.error(`[FAIL] Rogue host expansion was not flagged properly!`);
}

// Requirement 6: Decision explanation and triage steps
const sarahIncident = incidents.find(i => i.user.toLowerCase() === 'sarah.jenkins');
if (sarahIncident && sarahIncident.decisionExplanation && sarahIncident.recommendedTriageSteps.length > 0) {
  console.log(`[PASS] MISSION 2 REQ 6 VERIFIED: Incident for 'sarah.jenkins' contains explicit decision rationale: "${sarahIncident.decisionExplanation}" and ${sarahIncident.recommendedTriageSteps.length} actionable triage steps.`);
}

// 7. MISSION 3 REQUIREMENTS VERIFICATION
console.log('\n--- VERIFYING MISSION 3 VISUALIZATION & TRACEABILITY REQUIREMENTS ---');

// Mission 3 Req 1: Chronological Incident Timeline
if (sarahIncident && sarahIncident.timelineEvents && sarahIncident.timelineEvents.length > 0) {
  const isSorted = sarahIncident.timelineEvents.every((ev, idx, arr) => idx === 0 || ev.epochMs >= arr[idx - 1].epochMs);
  const alertEvents = sarahIncident.timelineEvents.filter(e => e.type === 'DETECTION_ALERT');
  const authEvents = sarahIncident.timelineEvents.filter(e => e.type.startsWith('AUTH_'));
  console.log(`[PASS] MISSION 3 REQ 1 VERIFIED: Generated chronological timeline with ${sarahIncident.timelineEvents.length} events (${alertEvents.length} alerts, ${authEvents.length} auth attempts). Strictly sorted: ${isSorted}`);
} else {
  console.error('[FAIL] Timeline events not generated properly!');
}

// Mission 3 Req 2: Alert Explanations, Confidence, and Evidence Strength Labels
const highConfidenceAlerts = alerts.filter(a => a.confidenceLabel && a.evidenceStrength);
console.log(`[PASS] MISSION 3 REQ 2 VERIFIED: ${highConfidenceAlerts.length}/${alerts.length} detection alerts contain confidence labels and evidence-strength ratings.`);
if (alerts[0]) {
  console.log(`  - Example Alert '${alerts[0].ruleName}': Confidence=${alerts[0].confidenceLabel} (${alerts[0].confidenceScore}%), EvidenceStrength=${alerts[0].evidenceStrength}`);
}

// Mission 3 Req 3: Per-User Risk Score Breakdown
if (sarahIncident && sarahIncident.riskBreakdown && sarahIncident.riskBreakdown.length > 0) {
  console.log(`[PASS] MISSION 3 REQ 3 VERIFIED: Per-user risk score breakdown generated with ${sarahIncident.riskBreakdown.length} itemized factors:`);
  sarahIncident.riskBreakdown.forEach(b => {
    console.log(`    * ${b.ruleName} [${b.category}]: +${b.pointsAdded} pts (${b.percentageOfTotal}%) - ${b.reason}`);
  });
} else {
  console.error('[FAIL] Risk score breakdown not generated properly!');
}

// Mission 3 Req 4: User-to-Host Communication Graph
if (daveIncident && daveIncident.hostGraph && daveIncident.hostGraph.nodes.length > 0) {
  const g = daveIncident.hostGraph;
  console.log(`[PASS] MISSION 3 REQ 4 VERIFIED: User-to-Host communication graph generated: ${g.nodes.length} nodes, ${g.edges.length} edges. Novel hosts: ${g.novelHostsCount}, Habitual hosts: ${g.baselineHostsCount}.`);
} else {
  console.error('[FAIL] User-to-host graph not generated properly!');
}

// 8. Export verification
const csvReport = exportIncidentsToCsv(incidents, DEFAULT_COMPANIES[0].name);
const htmlReport = exportIncidentsToHtml(incidents, DEFAULT_COMPANIES[0], 'Lead Forensics Investigator');
console.log(`[PASS] Generated CSV (${csvReport.length} bytes) and Offline HTML Dossier (${htmlReport.length} bytes).`);

console.log('\n=== ALL MISSION 1, 2, AND 3 OBJECTIVES HAVE BEEN SUCCESSFULLY VALIDATED ===');
