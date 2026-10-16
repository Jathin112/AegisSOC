import React, { useState } from 'react';
import { 
  X, 
  ShieldAlert, 
  Flame, 
  CheckSquare, 
  Square, 
  Send, 
  Clock, 
  Server, 
  Globe, 
  FileText, 
  AlertTriangle,
  History,
  CheckCircle2,
  Copy,
  Network,
  Layers,
  Activity,
  ListFilter
} from 'lucide-react';
import { UserIncident, UserBaseline, IncidentStatus, IncidentNote } from '../types';
import { formatUtcDateTime } from '../utils/timestampNormalizer';
import { RiskScoreBreakdownCard } from './RiskScoreBreakdownCard';
import { AlertExplanationCard } from './AlertExplanationCard';
import { IncidentTimelineVisualizer } from './IncidentTimelineVisualizer';
import { UserHostGraphVisualizer } from './UserHostGraphVisualizer';

interface IncidentDetailModalProps {
  incident: UserIncident | null;
  baseline?: UserBaseline;
  onClose: () => void;
  onUpdateStatus: (incidentId: string, status: IncidentStatus) => void;
  onAddNote: (incidentId: string, text: string) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  baseline,
  onClose,
  onUpdateStatus,
  onAddNote
}) => {
  if (!incident) return null;

  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'TIMELINE' | 'GRAPH' | 'ALERTS' | 'EVIDENCE'>('OVERVIEW');
  const [newNoteText, setNewNoteText] = useState('');
  const [completedSteps, setCompletedSteps] = useState<Record<number, boolean>>({});
  const [copiedLogId, setCopiedLogId] = useState<string | null>(null);

  const toggleStep = (idx: number) => {
    setCompletedSteps(prev => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteText.trim()) return;
    onAddNote(incident.id, newNoteText.trim());
    setNewNoteText('');
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedLogId(id);
    setTimeout(() => setCopiedLogId(null), 2000);
  };

  const isCompromise = incident.threatClass === 'CONFIRMED_COMPROMISE';
  const severityBadgeClass = `badge-${incident.severity.toLowerCase()}`;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: 1150, width: '95vw' }} onClick={e => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="modal-header">
          <div className="modal-title-group">
            <div className={`metric-icon-box ${isCompromise ? 'critical' : ''}`}>
              {isCompromise ? <Flame size={18} /> : <ShieldAlert size={18} />}
            </div>
            <div>
              <div className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                {incident.id} &mdash; Account: {incident.user}
                <span className={`badge ${severityBadgeClass}`}>{incident.severity} SEVERITY</span>
                {isCompromise ? (
                  <span className="badge badge-compromise">CONFIRMED COMPROMISE</span>
                ) : (
                  <span className="badge badge-suspicious">SUSPICIOUS INDICATION</span>
                )}
                {incident.isContextSuppressed && (
                  <span className="badge" style={{ backgroundColor: '#f0fdf4', color: '#166534', border: '1px solid #bbf7d0' }}>
                    BENIGN MAINTENANCE
                  </span>
                )}
              </div>
              <div style={{ fontSize: 11, color: 'var(--slate-500)', marginTop: 2 }}>
                First Observed: {formatUtcDateTime(incident.firstSeen)} &bull; Latest: {formatUtcDateTime(incident.lastSeen)}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--slate-500)' }}>STATUS:</span>
              <select
                className="filter-select"
                style={{ fontSize: 12, fontWeight: 600 }}
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
            </div>
            <button className="btn-close" onClick={onClose}>
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Modal Navigation Tabs (Mission 3 Interactive Workbench) */}
        <div 
          style={{ 
            display: 'flex', 
            gap: 4, 
            padding: '8px 20px', 
            backgroundColor: '#f8fafc', 
            borderBottom: '1px solid #e2e8f0',
            overflowX: 'auto'
          }}
        >
          <button
            className={`btn btn-sm ${activeTab === 'OVERVIEW' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('OVERVIEW')}
            style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Activity size={14} />
            Overview &amp; Triage
          </button>
          <button
            className={`btn btn-sm ${activeTab === 'TIMELINE' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('TIMELINE')}
            style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Clock size={14} />
            Incident Timeline ({incident.timelineEvents?.length || incident.evidenceRows.length})
          </button>
          <button
            className={`btn btn-sm ${activeTab === 'GRAPH' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('GRAPH')}
            style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Network size={14} />
            User-to-Host Graph ({incident.involvedHosts.length} Hosts)
          </button>
          <button
            className={`btn btn-sm ${activeTab === 'ALERTS' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('ALERTS')}
            style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <ShieldAlert size={14} />
            Alerts &amp; Explanations ({incident.alerts.length})
          </button>
          <button
            className={`btn btn-sm ${activeTab === 'EVIDENCE' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('EVIDENCE')}
            style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <FileText size={14} />
            Correlated Evidence ({incident.evidenceCount})
          </button>
        </div>

        {/* Modal Body */}
        <div className="modal-body" style={{ maxHeight: 'calc(85vh - 140px)', overflowY: 'auto' }}>
          {/* TAB 1: OVERVIEW & TRIAGE */}
          {activeTab === 'OVERVIEW' && (
            <div className="investigation-grid">
              {/* Left Column: Forensic Evidence & Baseline Comparison */}
              <div>
                {/* Context Decision & Rationale Card */}
                <div 
                  className="detail-card"
                  style={{
                    borderLeft: incident.isContextSuppressed ? '4px solid #16a34a' : isCompromise ? '4px solid #991b1b' : '4px solid #334155',
                    backgroundColor: incident.isContextSuppressed ? '#f0fdf4' : '#ffffff'
                  }}
                >
                  <div className="detail-card-title" style={{ color: incident.isContextSuppressed ? '#166534' : undefined }}>
                    <ShieldAlert size={14} />
                    Contextual Decision Analysis &amp; False-Positive Evaluation
                  </div>

                  <div style={{ fontSize: 12, color: incident.isContextSuppressed ? '#14532d' : '#1e293b', marginBottom: 8, lineHeight: 1.5 }}>
                    <strong>Decision Rationale:</strong> {incident.decisionExplanation || 'Standard detection heuristics applied.'}
                  </div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                    <span className="badge" style={{ backgroundColor: '#f1f5f9', color: '#334155', border: '1px solid #cbd5e1' }}>
                      Role: {incident.accountRole || 'REGULAR_USER'}
                    </span>
                    {incident.isHelpdesk && (
                      <span className="badge" style={{ backgroundColor: '#eff6ff', color: '#1e40af', border: '1px solid #bfdbfe' }}>
                        AUTHORIZED HELPDESK ACCOUNT
                      </span>
                    )}
                    {incident.isTravelingEmployee && (
                      <span className="badge" style={{ backgroundColor: '#f0fdf4', color: '#166534', border: '1px solid #bbf7d0' }}>
                        APPROVED CORPORATE TRAVELER
                      </span>
                    )}
                    {incident.contextFlags?.map(flag => (
                      <span key={flag} className="badge" style={{ backgroundColor: '#f8fafc', color: '#475569', border: '1px solid #e2e8f0' }}>
                        {flag}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Risk Score Breakdown Card (Mission 3) */}
                <RiskScoreBreakdownCard
                  score={incident.riskScore}
                  isCompromise={isCompromise}
                  isContextSuppressed={!!incident.isContextSuppressed}
                  breakdown={incident.riskBreakdown || []}
                />

                {/* Behavioral Baseline vs Anomaly Comparison */}
                <div className="detail-card">
                  <div className="detail-card-title">
                    <History size={14} />
                    Learned Baseline Profile vs. Observed Anomaly
                  </div>

                  {baseline ? (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 12 }}>
                      <div style={{ backgroundColor: '#f8fafc', padding: 10, borderRadius: 4, border: '1px solid #e2e8f0' }}>
                        <div style={{ fontWeight: 700, color: '#334155', marginBottom: 4 }}>
                          Learned Training Baseline ({baseline.trainingLogsCount} events)
                        </div>
                        <div style={{ color: '#475569', lineHeight: 1.6 }}>
                          <div><strong>Habitual Hours:</strong> {baseline.usualHours.length > 0 ? baseline.usualHours.map(h => `${h}:00`).join(', ') : 'None'}</div>
                          <div><strong>Whitelisted IPs:</strong> {baseline.usualIPs.slice(0, 3).join(', ') || 'N/A'}{baseline.usualIPs.length > 3 ? ` (+${baseline.usualIPs.length - 3})` : ''}</div>
                          <div><strong>Authorized Subnets:</strong> {baseline.usualSubnets.join(', ') || 'N/A'}</div>
                          <div><strong>Authorized Hosts:</strong> {baseline.usualHosts.join(', ') || 'N/A'}</div>
                        </div>
                      </div>

                      <div style={{ backgroundColor: '#fff7ed', padding: 10, borderRadius: 4, border: '1px solid #fed7aa' }}>
                        <div style={{ fontWeight: 700, color: '#9a3412', marginBottom: 4 }}>
                          Incident Deviations &amp; Anomalies
                        </div>
                        <div style={{ color: '#7c2d12', lineHeight: 1.6 }}>
                          <div><strong>Involved Origin IPs:</strong> {incident.involvedIPs.join(', ') || 'N/A'}</div>
                          <div><strong>Targeted Hosts:</strong> {incident.involvedHosts.join(', ') || 'N/A'}</div>
                          <div><strong>Triggered Rules:</strong> {incident.triggeredRuleCategories.length} rule types</div>
                          <div><strong>Attack Duration:</strong> {Math.max(1, Math.round((new Date(incident.lastSeen).getTime() - new Date(incident.firstSeen).getTime()) / 60000))} minute(s)</div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div style={{ fontSize: 12, color: 'var(--slate-500)', fontStyle: 'italic' }}>
                      No prior baseline observed for this account in the training period. Activity evaluated as entirely novel.
                    </div>
                  )}
                </div>
              </div>

              {/* Right Column: Risk Gauge, Triage Checklist, & Audit Notes */}
              <div>
                {/* Risk Score Summary */}
                <div className="detail-card" style={{ textAlign: 'center', backgroundColor: '#f8fafc' }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--slate-500)', textTransform: 'uppercase' }}>
                    Forensic Risk Score
                  </div>
                  <div 
                    style={{ 
                      fontSize: 48, 
                      fontWeight: 800, 
                      color: isCompromise ? '#991b1b' : incident.riskScore >= 60 ? '#c2410c' : '#166534',
                      lineHeight: 1.1,
                      margin: '6px 0'
                    }}
                  >
                    {incident.riskScore}
                    <span style={{ fontSize: 16, color: 'var(--slate-400)', fontWeight: 500 }}>/100</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--slate-600)', padding: '0 8px' }}>
                    {isCompromise
                      ? 'Confirmed intrusion: High-confidence attack progression detected with credential breach or multi-host takeover.'
                      : incident.isContextSuppressed
                      ? 'Benign operational activity: Verified maintenance window or approved VPN traveler. Threat score suppressed.'
                      : 'Suspicious behavioral deviation: Anomalous patterns observed relative to learned historical baseline.'}
                  </div>
                </div>

                {/* Recommended Triage Checklist */}
                <div className="detail-card">
                  <div className="detail-card-title">
                    <CheckSquare size={14} />
                    SOC Analyst Triage Checklist
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--slate-500)', marginBottom: 10 }}>
                    Click each task upon completion to verify containment &amp; eradication:
                  </p>
                  <ul className="triage-checklist">
                    {incident.recommendedTriageSteps.map((step, idx) => {
                      const isChecked = !!completedSteps[idx];
                      return (
                        <li
                          key={idx}
                          className={`triage-item ${isChecked ? 'checked' : ''}`}
                          onClick={() => toggleStep(idx)}
                        >
                          <input
                            type="checkbox"
                            className="triage-checkbox"
                            checked={isChecked}
                            onChange={() => {}}
                          />
                          <span>{step}</span>
                        </li>
                      );
                    })}
                  </ul>
                </div>

                {/* Incident Notes & Audit Journal */}
                <div className="detail-card">
                  <div className="detail-card-title">
                    <FileText size={14} />
                    Analyst Investigation Journal
                  </div>

                  <div style={{ maxHeight: 220, overflowY: 'auto', marginBottom: 12 }}>
                    {incident.notes.map((note) => (
                      <div key={note.id} className="note-box">
                        <div className="note-header">
                          <strong>{note.author}</strong> &bull; <span>{formatUtcDateTime(note.timestamp)}</span>
                        </div>
                        <p className="note-body">{note.text}</p>
                      </div>
                    ))}
                  </div>

                  <form onSubmit={handleAddNote} style={{ display: 'flex', gap: 6 }}>
                    <input
                      type="text"
                      className="search-input"
                      style={{ fontSize: 11, padding: '6px 10px' }}
                      placeholder="Add forensic finding or analyst note..."
                      value={newNoteText}
                      onChange={(e) => setNewNoteText(e.target.value)}
                    />
                    <button type="submit" className="btn btn-primary btn-sm">
                      <Send size={11} />
                      Log
                    </button>
                  </form>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: INTERACTIVE CHRONOLOGICAL TIMELINE (Mission 3) */}
          {activeTab === 'TIMELINE' && (
            <IncidentTimelineVisualizer
              events={incident.timelineEvents || []}
              incident={incident}
            />
          )}

          {/* TAB 3: USER-TO-HOST COMMUNICATION GRAPH (Mission 3) */}
          {activeTab === 'GRAPH' && (
            <UserHostGraphVisualizer
              graph={incident.hostGraph}
              incident={incident}
            />
          )}

          {/* TAB 4: ALERT EXPLANATIONS & EVIDENCE STRENGTH (Mission 3) */}
          {activeTab === 'ALERTS' && (
            <AlertExplanationCard alerts={incident.alerts} />
          )}

          {/* TAB 5: CORRELATED EVIDENCE TABLE */}
          {activeTab === 'EVIDENCE' && (
            <div className="detail-card">
              <div className="detail-card-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <FileText size={14} />
                  Correlated Evidence Logs ({incident.evidenceCount} events)
                </div>
                <span style={{ fontSize: 11, color: 'var(--slate-500)' }}>
                  Deterministic FNV-1a normalized event telemetry
                </span>
              </div>

              <div style={{ overflowX: 'auto', border: '1px solid #e2e8f0', borderRadius: 4 }}>
                <table className="soc-table" style={{ fontSize: 11 }}>
                  <thead>
                    <tr>
                      <th>Normalized Time (UTC)</th>
                      <th>Source IP</th>
                      <th>Target Host</th>
                      <th>Action</th>
                      <th>Failure / Event Reason</th>
                      <th>Location</th>
                      <th>Copy</th>
                    </tr>
                  </thead>
                  <tbody>
                    {incident.evidenceRows.map((ev) => (
                      <tr key={ev.id}>
                        <td className="mono">{formatUtcDateTime(ev.timestamp)}</td>
                        <td className="mono">{ev.ip}</td>
                        <td className="mono">{ev.host}</td>
                        <td>
                          <span 
                            className="badge"
                            style={{ 
                              backgroundColor: ev.action === 'SUCCESS' ? '#f0fdf4' : '#fef2f2',
                              color: ev.action === 'SUCCESS' ? '#166534' : '#991b1b',
                              border: `1px solid ${ev.action === 'SUCCESS' ? '#bbf7d0' : '#fecaca'}`
                            }}
                          >
                            {ev.action}
                          </span>
                        </td>
                        <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ev.failureReason}>
                          {ev.failureReason}
                        </td>
                        <td style={{ color: 'var(--slate-500)' }}>{ev.location}</td>
                        <td>
                          <button
                            className="btn btn-secondary btn-sm"
                            style={{ padding: '2px 5px', fontSize: 10 }}
                            onClick={() => handleCopy(`${ev.timestamp} | ${ev.user} | ${ev.ip} | ${ev.host} | ${ev.action} | ${ev.failureReason}`, ev.id)}
                            title="Copy raw event"
                          >
                            {copiedLogId === ev.id ? <CheckCircle2 size={11} color="#16a34a" /> : <Copy size={11} />}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: 11, color: 'var(--slate-500)' }}>
            Investigation Dossier &bull; Account: <strong>{incident.user}</strong> &bull; Threat Class: <strong>{incident.threatClass}</strong>
          </div>
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
