import React from 'react';
import { 
  ShieldAlert, 
  Flame, 
  ExternalLink, 
  Server, 
  Globe, 
  CheckCircle2, 
  Layers,
  Wrench,
  Plane
} from 'lucide-react';
import { UserIncident, IncidentStatus } from '../types';
import { formatUtcDateTime } from '../utils/timestampNormalizer';

interface IncidentTableProps {
  incidents: UserIncident[];
  onSelectIncident: (incident: UserIncident) => void;
  onUpdateStatus: (incidentId: string, status: IncidentStatus) => void;
}

export const IncidentTable: React.FC<IncidentTableProps> = ({
  incidents,
  onSelectIncident,
  onUpdateStatus
}) => {
  if (incidents.length === 0) {
    return (
      <div className="table-container">
        <div className="empty-state">
          <ShieldAlert size={36} className="empty-icon" />
          <div className="empty-title">No Security Incidents Detected</div>
          <div className="empty-desc">
            No authentication anomalies matching the current filter criteria were identified.
            Try adjusting filters or ingesting additional authentication logs.
          </div>
        </div>
      </div>
    );
  }

  const getScoreFillColor = (score: number, isSuppressed: boolean = false): string => {
    if (isSuppressed) return '#16a34a';
    if (score >= 80) return '#b91c1c';
    if (score >= 60) return '#c2410c';
    if (score >= 35) return '#b45309';
    return '#0369a1';
  };

  const formatCategoryPill = (cat: string): string => {
    switch (cat) {
      case 'BURST_FAILURE_THEN_SUCCESS': return 'Failure Burst &rarr; Success';
      case 'REPEATED_FAILURES': return 'Brute Force Failures';
      case 'PASSWORD_SPRAY': return 'Password Spray';
      case 'HOST_EXPANSION': return 'Lateral Host Expansion';
      case 'UNUSUAL_TIME': return 'Off-Hours Anomaly';
      case 'UNFAMILIAR_IP': return 'Unfamiliar IP';
      default: return cat.replace(/_/g, ' ');
    }
  };

  return (
    <div className="table-container">
      <table className="soc-table">
        <thead>
          <tr>
            <th style={{ width: 95 }}>Risk Score</th>
            <th>Target Account &amp; Role</th>
            <th>Classification &amp; Context</th>
            <th>Severity</th>
            <th>Triggered Anomalies</th>
            <th>Decision &amp; Contextual Rationale</th>
            <th>Involved Assets</th>
            <th>Status</th>
            <th style={{ textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => {
            const isCompromise = incident.threatClass === 'CONFIRMED_COMPROMISE';
            const isSuppressed = incident.isContextSuppressed;
            const severityBadgeClass = `badge-${incident.severity.toLowerCase()}`;

            return (
              <tr 
                key={incident.id} 
                style={{ 
                  backgroundColor: isSuppressed ? '#fcfdfd' : isCompromise ? '#fffbfb' : undefined,
                  opacity: isSuppressed ? 0.9 : 1
                }}
              >
                {/* Risk Score */}
                <td>
                  <div className="risk-meter">
                    <span 
                      className="risk-score-pill" 
                      style={{ 
                        backgroundColor: getScoreFillColor(incident.riskScore, isSuppressed) + '15',
                        color: getScoreFillColor(incident.riskScore, isSuppressed),
                        border: `1px solid ${getScoreFillColor(incident.riskScore, isSuppressed)}40`
                      }}
                    >
                      {incident.riskScore}
                    </span>
                    <div className="risk-bar-track">
                      <div
                        className="risk-bar-fill"
                        style={{
                          width: `${Math.max(8, incident.riskScore)}%`,
                          backgroundColor: getScoreFillColor(incident.riskScore, isSuppressed)
                        }}
                      />
                    </div>
                  </div>
                </td>

                {/* Target Account & Role */}
                <td>
                  <div className="user-cell">
                    <div 
                      className="user-avatar"
                      style={{
                        backgroundColor: isSuppressed ? '#166534' : isCompromise ? '#991b1b' : '#334155',
                        color: '#ffffff'
                      }}
                    >
                      {incident.user.substring(0, 2).toUpperCase()}
                    </div>
                    <div>
                      <div className="user-name" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {incident.user}
                        {incident.isHelpdesk && (
                          <span className="badge" style={{ backgroundColor: '#eff6ff', color: '#1e40af', border: '1px solid #bfdbfe', fontSize: 9 }}>
                            <Wrench size={9} /> HELPDESK
                          </span>
                        )}
                        {incident.isTravelingEmployee && (
                          <span className="badge" style={{ backgroundColor: '#f0fdf4', color: '#166534', border: '1px solid #bbf7d0', fontSize: 9 }}>
                            <Plane size={9} /> TRAVELER
                          </span>
                        )}
                      </div>
                      <div className="user-account-id mono">{incident.id}</div>
                    </div>
                  </div>
                </td>

                {/* Threat Classification & Context */}
                <td>
                  {isSuppressed ? (
                    <span className="badge" style={{ backgroundColor: '#f0fdf4', color: '#166534', border: '1px solid #bbf7d0' }}>
                      <CheckCircle2 size={11} />
                      BENIGN MAINTENANCE
                    </span>
                  ) : isCompromise ? (
                    <span className="badge badge-compromise">
                      <Flame size={11} />
                      CONFIRMED COMPROMISE
                    </span>
                  ) : (
                    <span className="badge badge-suspicious">
                      <ShieldAlert size={11} />
                      SUSPICIOUS INDICATION
                    </span>
                  )}
                </td>

                {/* Severity */}
                <td>
                  <span className={`badge ${severityBadgeClass}`}>
                    {incident.severity}
                  </span>
                </td>

                {/* Triggered Anomalies */}
                <td>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, maxWidth: 220 }}>
                    {incident.triggeredRuleCategories.map(cat => (
                      <span 
                        key={cat} 
                        className="badge-rule-pill"
                        dangerouslySetInnerHTML={{ __html: formatCategoryPill(cat) }}
                      />
                    ))}
                  </div>
                </td>

                {/* Decision Rationale */}
                <td style={{ maxWidth: 300 }}>
                  <div 
                    style={{ 
                      fontSize: 11, 
                      color: isSuppressed ? '#166534' : 'var(--slate-700)',
                      lineHeight: 1.4,
                      display: '-webkit-box',
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: 'vertical',
                      overflow: 'hidden'
                    }}
                    title={incident.decisionExplanation}
                  >
                    {incident.decisionExplanation || 'Standard anomaly scoring applied.'}
                  </div>
                </td>

                {/* Involved Hosts & IPs */}
                <td>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--slate-700)' }}>
                      <Server size={11} className="text-muted" />
                      <span className="mono">{incident.involvedHosts.slice(0, 2).join(', ') || 'N/A'}{incident.involvedHosts.length > 2 ? ` (+${incident.involvedHosts.length - 2})` : ''}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--slate-500)' }}>
                      <Globe size={11} className="text-muted" />
                      <span className="mono">{incident.involvedIPs.slice(0, 2).join(', ') || 'N/A'}{incident.involvedIPs.length > 2 ? ` (+${incident.involvedIPs.length - 2})` : ''}</span>
                    </div>
                  </div>
                </td>

                {/* Incident Status */}
                <td>
                  <select
                    className="filter-select"
                    style={{ fontSize: 11, padding: '3px 6px' }}
                    value={incident.status}
                    onChange={(e) => onUpdateStatus(incident.id, e.target.value as IncidentStatus)}
                  >
                    <option value="NEW">NEW</option>
                    <option value="INVESTIGATING">INVESTIGATING</option>
                    <option value="ESCALATED">ESCALATED</option>
                    <option value="BENIGN_MAINTENANCE">BENIGN MAINTENANCE</option>
                    <option value="REMEDIATED">REMEDIATED</option>
                    <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
                  </select>
                </td>

                {/* Actions */}
                <td style={{ textAlign: 'right' }}>
                  <button
                    className={`btn btn-sm ${isSuppressed ? 'btn-secondary' : 'btn-primary'}`}
                    onClick={() => onSelectIncident(incident)}
                  >
                    <ExternalLink size={12} />
                    Triage
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
