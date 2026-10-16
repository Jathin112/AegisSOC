import { UserIncident, CompanyAccessConfig } from '../types';
import { formatUtcDateTime } from './timestampNormalizer';

/**
 * Exports incidents to standard CSV format
 */
export function exportIncidentsToCsv(incidents: UserIncident[], companyName: string): string {
  const headers = [
    'Incident_ID',
    'Company',
    'User',
    'Risk_Score',
    'Severity',
    'Threat_Class',
    'Status',
    'Triggered_Rules',
    'First_Seen_UTC',
    'Last_Seen_UTC',
    'Involved_Hosts',
    'Involved_IPs',
    'Evidence_Count',
    'Recommended_Triage_Steps'
  ];

  const rows = incidents.map(inc => [
    `"${inc.id}"`,
    `"${companyName.replace(/"/g, '""')}"`,
    `"${inc.user.replace(/"/g, '""')}"`,
    inc.riskScore,
    `"${inc.severity}"`,
    `"${inc.threatClass}"`,
    `"${inc.status}"`,
    `"${inc.triggeredRuleCategories.join('; ')}"`,
    `"${formatUtcDateTime(inc.firstSeen)}"`,
    `"${formatUtcDateTime(inc.lastSeen)}"`,
    `"${inc.involvedHosts.join(', ')}"`,
    `"${inc.involvedIPs.join(', ')}"`,
    inc.evidenceCount,
    `"${inc.recommendedTriageSteps.join(' | ').replace(/"/g, '""')}"`
  ]);

  return [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');
}

/**
 * Exports standalone, print-ready, offline HTML SOC Incident Investigation Report
 */
export function exportIncidentsToHtml(
  incidents: UserIncident[],
  company: CompanyAccessConfig,
  analystName: string = 'SOC Level 2 Analyst'
): string {
  const generatedAt = formatUtcDateTime(new Date());

  const criticalCount = incidents.filter(i => i.severity === 'CRITICAL').length;
  const highCount = incidents.filter(i => i.severity === 'HIGH').length;
  const mediumCount = incidents.filter(i => i.severity === 'MEDIUM').length;
  const lowCount = incidents.filter(i => i.severity === 'LOW').length;
  const confirmedCompromises = incidents.filter(i => i.threatClass === 'CONFIRMED_COMPROMISE').length;

  const incidentsHtml = incidents.map((inc, idx) => {
    const severityBadgeClass = `badge-${inc.severity.toLowerCase()}`;
    const threatClassBadge = inc.threatClass === 'CONFIRMED_COMPROMISE' 
      ? '<span class="badge badge-compromise">CONFIRMED COMPROMISE</span>'
      : '<span class="badge badge-suspicious">SUSPICIOUS INDICATION</span>';

    const evidenceRowsHtml = inc.evidenceRows.slice(0, 15).map(ev => `
      <tr>
        <td class="mono">${formatUtcDateTime(ev.timestamp)}</td>
        <td class="mono">${ev.ip}</td>
        <td class="mono">${ev.host}</td>
        <td><span class="status-${ev.action.toLowerCase()}">${ev.action}</span></td>
        <td>${ev.failureReason}</td>
        <td>${ev.location}</td>
      </tr>
    `).join('');

    const triageStepsHtml = inc.recommendedTriageSteps.map(step => `
      <li>${step}</li>
    `).join('');

    const notesHtml = inc.notes.map(n => `
      <div class="note-box">
        <div class="note-header"><strong>${n.author}</strong> - <span>${formatUtcDateTime(n.timestamp)}</span></div>
        <p class="note-body">${n.text}</p>
      </div>
    `).join('');

    return `
    <div class="incident-card">
      <div class="incident-header">
        <div>
          <div class="incident-id">${inc.id} <span class="incident-user">Target Account: <strong>${inc.user}</strong></span></div>
          <div class="incident-meta">
            Window: ${formatUtcDateTime(inc.firstSeen)} &mdash; ${formatUtcDateTime(inc.lastSeen)} | 
            Hosts: <strong>${inc.involvedHosts.join(', ') || 'N/A'}</strong> | 
            Origin IPs: <strong>${inc.involvedIPs.join(', ') || 'N/A'}</strong>
          </div>
        </div>
        <div class="score-container">
          <div class="score-badge ${severityBadgeClass}">
            <div class="score-number">${inc.riskScore}</div>
            <div class="score-label">RISK SCORE</div>
          </div>
        </div>
      </div>

      <div class="incident-tags">
        <span class="badge ${severityBadgeClass}">${inc.severity} SEVERITY</span>
        ${threatClassBadge}
        <span class="badge badge-status">STATUS: ${inc.status}</span>
        ${inc.triggeredRuleCategories.map(cat => `<span class="badge badge-rule">${cat.replace(/_/g, ' ')}</span>`).join(' ')}
      </div>

      <div class="section-title">Recommended SOC Triage Procedures</div>
      <ol class="triage-list">
        ${triageStepsHtml}
      </ol>

      <div class="section-title">Correlated Evidence Logs (${inc.evidenceCount} Total Records${inc.evidenceCount > 15 ? ' - Top 15 shown' : ''})</div>
      <div class="table-wrapper">
        <table class="evidence-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Source IP</th>
              <th>Target Host</th>
              <th>Action</th>
              <th>Details / Reason</th>
              <th>Geo / Location</th>
            </tr>
          </thead>
          <tbody>
            ${evidenceRowsHtml}
          </tbody>
        </table>
      </div>

      ${inc.notes.length > 0 ? `
        <div class="section-title">Analyst Audit Notes</div>
        ${notesHtml}
      ` : ''}
    </div>
    `;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AegisSOC Incident Investigation Report - ${company.name}</title>
  <style>
    @page { margin: 15mm; size: A4; }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #ffffff;
      color: #1e293b;
      margin: 0;
      padding: 30px;
      font-size: 13px;
      line-height: 1.5;
    }
    .header {
      border-bottom: 2px solid #0f172a;
      padding-bottom: 16px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    .logo-title {
      font-size: 24px;
      font-weight: 800;
      color: #0f172a;
      letter-spacing: -0.5px;
    }
    .logo-subtitle {
      font-size: 12px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-top: 2px;
    }
    .report-meta {
      text-align: right;
      font-size: 11px;
      color: #475569;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-bottom: 28px;
    }
    .stat-card {
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 12px;
      background: #f8fafc;
      text-align: center;
    }
    .stat-number {
      font-size: 26px;
      font-weight: 700;
      color: #0f172a;
    }
    .stat-label {
      font-size: 10px;
      font-weight: 600;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-top: 4px;
    }
    .stat-critical .stat-number { color: #b91c1c; }
    .stat-compromise .stat-number { color: #991b1b; }
    .stat-high .stat-number { color: #c2410c; }
    
    .incident-card {
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
      background: #ffffff;
      page-break-inside: avoid;
    }
    .incident-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 12px;
      margin-bottom: 12px;
    }
    .incident-id {
      font-size: 16px;
      font-weight: 700;
      color: #0f172a;
    }
    .incident-user {
      margin-left: 12px;
      color: #334155;
    }
    .incident-meta {
      font-size: 11px;
      color: #64748b;
      margin-top: 4px;
    }
    .score-badge {
      border-radius: 6px;
      padding: 6px 14px;
      text-align: center;
      min-width: 80px;
    }
    .score-number {
      font-size: 22px;
      font-weight: 800;
      line-height: 1;
    }
    .score-label {
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.5px;
      margin-top: 2px;
    }
    .badge-critical { background-color: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; }
    .badge-high { background-color: #fff7ed; border: 1px solid #fed7aa; color: #c2410c; }
    .badge-medium { background-color: #fffbeb; border: 1px solid #fde68a; color: #b45309; }
    .badge-low { background-color: #f0f9ff; border: 1px solid #bae6fd; color: #0369a1; }
    
    .incident-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 16px;
    }
    .badge {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-compromise { background-color: #7f1d1d; color: #ffffff; }
    .badge-suspicious { background-color: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }
    .badge-status { background-color: #f8fafc; border: 1px solid #cbd5e1; color: #334155; }
    .badge-rule { background-color: #f1f5f9; border: 1px solid #e2e8f0; color: #1e293b; }
    
    .section-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #475569;
      margin: 14px 0 6px 0;
    }
    .triage-list {
      margin: 0 0 16px 20px;
      padding: 0;
      color: #1e293b;
    }
    .triage-list li {
      margin-bottom: 4px;
    }
    .table-wrapper {
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      overflow: hidden;
      margin-bottom: 16px;
    }
    .evidence-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
    }
    .evidence-table th {
      background-color: #f1f5f9;
      color: #475569;
      font-weight: 600;
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid #e2e8f0;
    }
    .evidence-table td {
      padding: 7px 10px;
      border-bottom: 1px solid #f1f5f9;
    }
    .evidence-table tr:last-child td { border-bottom: none; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .status-success { color: #15803d; font-weight: 600; }
    .status-failure { color: #b91c1c; font-weight: 600; }
    
    .note-box {
      background: #f8fafc;
      border-left: 3px solid #64748b;
      padding: 8px 12px;
      margin-bottom: 8px;
      border-radius: 0 4px 4px 0;
    }
    .note-header {
      font-size: 11px;
      color: #64748b;
      margin-bottom: 2px;
    }
    .note-body { margin: 0; color: #334155; }
    
    .signoff-section {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px dashed #cbd5e1;
      display: flex;
      justify-content: space-between;
      page-break-inside: avoid;
    }
    .signoff-box {
      width: 45%;
    }
    .signoff-line {
      border-bottom: 1px solid #0f172a;
      height: 35px;
      margin-bottom: 6px;
    }
    .signoff-label {
      font-size: 11px;
      color: #64748b;
    }
    @media print {
      body { padding: 0; }
      .incident-card { box-shadow: none; border-color: #94a3b8; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <div class="logo-title">AEGIS SOC // LOG ANALYSIS & INCIDENT REPORT</div>
      <div class="logo-subtitle">Enterprise Security Operations Center &bull; Offline Forensic Intelligence</div>
    </div>
    <div class="report-meta">
      <div><strong>Target Organization:</strong> ${company.name} (${company.code})</div>
      <div><strong>Report Generated:</strong> ${generatedAt}</div>
      <div><strong>Lead SOC Analyst:</strong> ${analystName}</div>
      <div><strong>Classification:</strong> RESTRICTED / SOC-INTERNAL</div>
    </div>
  </div>

  <div class="summary-grid">
    <div class="stat-card">
      <div class="stat-number">${incidents.length}</div>
      <div class="stat-label">Total Incidents</div>
    </div>
    <div class="stat-card stat-compromise">
      <div class="stat-number">${confirmedCompromises}</div>
      <div class="stat-label">Confirmed Compromises</div>
    </div>
    <div class="stat-card stat-critical">
      <div class="stat-number">${criticalCount}</div>
      <div class="stat-label">Critical Severity</div>
    </div>
    <div class="stat-card stat-high">
      <div class="stat-number">${highCount}</div>
      <div class="stat-label">High Severity</div>
    </div>
    <div class="stat-card">
      <div class="stat-number">${mediumCount + lowCount}</div>
      <div class="stat-label">Medium / Low</div>
    </div>
  </div>

  ${incidentsHtml}

  <div class="signoff-section">
    <div class="signoff-box">
      <div class="signoff-line"></div>
      <div class="signoff-label">Investigating Analyst Signature &amp; Date (${analystName})</div>
    </div>
    <div class="signoff-box">
      <div class="signoff-line"></div>
      <div class="signoff-label">Incident Response Commander / CISO Approval</div>
    </div>
  </div>
</body>
</html>`;
}
