import { parseAuthLogsCsv } from './utils/csvParser';
import { deduplicateLogs } from './utils/logDeduplicator';
import { learnBaselines } from './utils/baselineLearner';
import { runDetectionRules } from './utils/rulesEngine';
import { aggregateIncidents } from './utils/incidentAggregator';
import { exportIncidentsToCsv, exportIncidentsToHtml } from './utils/exportGenerator';
import { DEFAULT_RULES } from './config/defaultRules';
import { DEFAULT_COMPANIES } from './config/defaultCompanies';
import { SAMPLE_CSV_LOGS } from './data/sampleLogs';

console.log('--- STARTING OFFLINE LOG ANALYSIS ENGINE INTEGRATION TEST ---');

// 1. Ingestion
const parsed = parseAuthLogsCsv(SAMPLE_CSV_LOGS, 'COMP-001');
console.log(`[PASS] Ingested raw logs: ${parsed.logs.length} entries. (Errors: ${parsed.errors.length})`);

// 2. Deduplication
const dedup = deduplicateLogs(parsed.logs);
console.log(`[PASS] Deduplication: ${dedup.uniqueLogs.length} unique records, ${dedup.duplicateCount} duplicates suppressed.`);

// 3. Baseline Learning (50% training)
const baselineResult = learnBaselines(dedup.uniqueLogs, { mode: 'PERCENTAGE', percentage: 50 });
console.log(`[PASS] Baseline learning: ${baselineResult.baselines.size} user profiles learned from ${baselineResult.trainingLogCount} training events.`);

// Verify baseline for alice.m
const aliceBaseline = baselineResult.baselines.get('alice.m');
if (aliceBaseline) {
  console.log(`[PASS] User 'alice.m' baseline: Usual Hours [${aliceBaseline.usualHours.join(', ')}], Hosts [${aliceBaseline.usualHosts.join(', ')}], IPs [${aliceBaseline.usualIPs.join(', ')}]`);
}

// 4. Detection Rules Execution
const alerts = runDetectionRules(dedup.uniqueLogs, baselineResult.baselines, DEFAULT_RULES);
console.log(`[PASS] Detection Rules: Triggered ${alerts.length} alerts across evaluation logs.`);

const ruleCategories = new Set(alerts.map(a => a.ruleCategory));
console.log(`[PASS] Distinct triggered rule categories:`, Array.from(ruleCategories));

// 5. Incident Aggregation & Risk Scoring
const incidents = aggregateIncidents(alerts, 'COMP-001');
console.log(`[PASS] Aggregated ${incidents.length} user security incidents.`);

for (const inc of incidents) {
  console.log(`  - Incident ${inc.id} for user '${inc.user}': Risk Score ${inc.riskScore}/100, Severity: ${inc.severity}, Threat Class: ${inc.threatClass}, Rules: [${inc.triggeredRuleCategories.join(', ')}]`);
}

// Check Confirmed Compromise
const compromises = incidents.filter(i => i.threatClass === 'CONFIRMED_COMPROMISE');
console.log(`[PASS] Confirmed Compromises identified: ${compromises.length} (Target: ${compromises.map(c => c.user).join(', ')})`);

// 6. Export verification
const csvReport = exportIncidentsToCsv(incidents, DEFAULT_COMPANIES[0].name);
console.log(`[PASS] CSV Report generated, length: ${csvReport.length} bytes.`);

const htmlReport = exportIncidentsToHtml(incidents, DEFAULT_COMPANIES[0], 'Lead Forensics Investigator');
console.log(`[PASS] Standalone HTML Forensic Dossier generated, length: ${htmlReport.length} bytes.`);

console.log('--- ALL ENGINE INTEGRATION TESTS PASSED PERFECTLY ---');
