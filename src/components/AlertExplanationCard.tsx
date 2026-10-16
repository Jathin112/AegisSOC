import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ChevronDown, 
  ChevronUp, 
  CheckCircle2, 
  Copy, 
  AlertTriangle, 
  Gauge, 
  FileCheck 
} from 'lucide-react';
import { DetectionAlert } from '../types';
import { formatUtcDateTime } from '../utils/timestampNormalizer';

interface AlertExplanationCardProps {
  alerts: DetectionAlert[];
}

export const AlertExplanationCard: React.FC<AlertExplanationCardProps> = ({ alerts }) => {
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(alerts[0]?.id || null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const toggleExpand = (id: string) => {
    setExpandedAlertId(prev => prev === id ? null : id);
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getConfidenceBadge = (confidence?: string, score?: number) => {
    switch (confidence) {
      case 'VERY_HIGH':
        return { bg: '#fef2f2', text: '#991b1b', border: '#fecaca', label: `VERY HIGH (${score ?? 95}%)` };
      case 'HIGH':
        return { bg: '#fff7ed', text: '#c2410c', border: '#fed7aa', label: `HIGH (${score ?? 85}%)` };
      case 'MODERATE':
        return { bg: '#fefce8', text: '#854d0e', border: '#fef08a', label: `MODERATE (${score ?? 65}%)` };
      case 'LOW':
      default:
        return { bg: '#f0fdf4', text: '#166534', border: '#bbf7d0', label: `LOW (${score ?? 25}%)` };
    }
  };

  const getStrengthBadge = (strength?: string) => {
    switch (strength) {
      case 'VERY_STRONG':
        return { bg: '#f8fafc', text: '#0f172a', border: '#cbd5e1', label: 'VERY STRONG EVIDENCE' };
      case 'STRONG':
        return { bg: '#f8fafc', text: '#1e293b', border: '#e2e8f0', label: 'STRONG EVIDENCE' };
      case 'MODERATE':
        return { bg: '#f8fafc', text: '#475569', border: '#e2e8f0', label: 'MODERATE EVIDENCE' };
      case 'WEAK':
      default:
        return { bg: '#f8fafc', text: '#64748b', border: '#e2e8f0', label: 'WEAK SIGNAL (MITIGATED)' };
    }
  };

  return (
    <div className="detail-card">
      <div className="detail-card-title">
        <ShieldAlert size={15} />
        Alert Explanations &amp; Evidence-Strength Analysis ({alerts.length} Alert{alerts.length !== 1 ? 's' : ''})
      </div>
      <div style={{ fontSize: 11, color: 'var(--slate-600)', marginBottom: 12 }}>
        Transparent forensic explanations for each detection rule triggered, supporting evidence logs, and calculated confidence levels.
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {alerts.map((alt) => {
          const isExpanded = expandedAlertId === alt.id;
          const confBadge = getConfidenceBadge(alt.confidenceLabel, alt.confidenceScore);
          const strengthBadge = getStrengthBadge(alt.evidenceStrength);
          const isCompromise = alt.threatClass === 'CONFIRMED_COMPROMISE';

          return (
            <div 
              key={alt.id}
              style={{
                border: '1px solid #e2e8f0',
                borderRadius: 4,
                backgroundColor: isExpanded ? '#ffffff' : '#f8fafc',
                overflow: 'hidden'
              }}
            >
              {/* Alert Header Row */}
              <div 
                style={{
                  padding: '10px 12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  cursor: 'pointer',
                  borderBottom: isExpanded ? '1px solid #e2e8f0' : 'none',
                  backgroundColor: isExpanded ? '#f1f5f9' : '#f8fafc'
                }}
                onClick={() => toggleExpand(alt.id)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  <span style={{ fontWeight: 700, fontSize: 12, color: 'var(--slate-800)' }}>
                    {alt.ruleName}
                  </span>
                  
                  {/* Confidence Badge */}
                  <span 
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      padding: '2px 6px',
                      borderRadius: 4,
                      backgroundColor: confBadge.bg,
                      color: confBadge.text,
                      border: `1px solid ${confBadge.border}`,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 4
                    }}
                    title="Analyst confidence rating based on behavioral correlation and context verification"
                  >
                    <Gauge size={11} />
                    Confidence: {confBadge.label}
                  </span>

                  {/* Evidence Strength Badge */}
                  <span 
                    style={{
                      fontSize: 10,
                      fontWeight: 600,
                      padding: '2px 6px',
                      borderRadius: 4,
                      backgroundColor: strengthBadge.bg,
                      color: strengthBadge.text,
                      border: `1px solid ${strengthBadge.border}`,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 4
                    }}
                  >
                    <FileCheck size={11} />
                    {strengthBadge.label}
                  </span>

                  {alt.isContextSuppressed && (
                    <span 
                      style={{
                        fontSize: 10,
                        fontWeight: 600,
                        padding: '2px 6px',
                        borderRadius: 4,
                        backgroundColor: '#f0fdf4',
                        color: '#166534',
                        border: '1px solid #bbf7d0'
                      }}
                    >
                      SUPPRESSED IN SCHEDULE
                    </span>
                  )}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 11, color: 'var(--slate-500)', fontFamily: 'monospace' }}>
                    {alt.evidence?.length || 1} event(s)
                  </span>
                  {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                </div>
              </div>

              {/* Expanded Alert Detail */}
              {isExpanded && (
                <div style={{ padding: 12, fontSize: 11, backgroundColor: '#ffffff' }}>
                  {/* Decision Explanation Box */}
                  <div 
                    style={{ 
                      padding: '8px 12px', 
                      backgroundColor: alt.isContextSuppressed ? '#f0fdf4' : isCompromise ? '#fef2f2' : '#f8fafc',
                      borderRadius: 4,
                      borderLeft: `3px solid ${alt.isContextSuppressed ? '#16a34a' : isCompromise ? '#991b1b' : '#334155'}`,
                      marginBottom: 10,
                      color: alt.isContextSuppressed ? '#14532d' : isCompromise ? '#7f1d1d' : '#1e293b'
                    }}
                  >
                    <strong>Decision Explanation &amp; Forensic Rationale:</strong>
                    <div style={{ marginTop: 4, lineHeight: 1.5 }}>
                      {alt.decisionExplanation || alt.summary}
                    </div>
                  </div>

                  {/* Supporting Evidence Sub-Table */}
                  <div style={{ marginTop: 8 }}>
                    <div style={{ fontWeight: 600, color: 'var(--slate-700)', marginBottom: 4, display: 'flex', justifyContent: 'space-between' }}>
                      <span>Supporting Evidence Logs ({alt.evidence?.length || 0} event{alt.evidence?.length !== 1 ? 's' : ''})</span>
                      <span style={{ fontSize: 10, color: 'var(--slate-500)' }}>Normalized UTC Timestamps</span>
                    </div>

                    <div style={{ maxHeight: 180, overflowY: 'auto', border: '1px solid #e2e8f0', borderRadius: 4 }}>
                      <table className="soc-table" style={{ fontSize: 10 }}>
                        <thead>
                          <tr>
                            <th>Timestamp (UTC)</th>
                            <th>Action</th>
                            <th>Host</th>
                            <th>IP</th>
                            <th>Reason</th>
                            <th>Copy</th>
                          </tr>
                        </thead>
                        <tbody>
                          {alt.evidence?.map((ev) => (
                            <tr key={ev.id}>
                              <td className="mono">{formatUtcDateTime(ev.timestamp)}</td>
                              <td>
                                <span 
                                  className="badge" 
                                  style={{ 
                                    padding: '1px 4px', 
                                    fontSize: 9,
                                    backgroundColor: ev.action === 'SUCCESS' ? '#f0fdf4' : '#fef2f2',
                                    color: ev.action === 'SUCCESS' ? '#166534' : '#991b1b',
                                    border: `1px solid ${ev.action === 'SUCCESS' ? '#bbf7d0' : '#fecaca'}`
                                  }}
                                >
                                  {ev.action}
                                </span>
                              </td>
                              <td className="mono">{ev.host}</td>
                              <td className="mono">{ev.ip}</td>
                              <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ev.failureReason}>
                                {ev.failureReason}
                              </td>
                              <td>
                                <button
                                  className="btn btn-secondary btn-sm"
                                  style={{ padding: '1px 4px', fontSize: 9 }}
                                  onClick={() => handleCopy(`${ev.timestamp} | ${ev.user} | ${ev.ip} | ${ev.host} | ${ev.action} | ${ev.failureReason}`, ev.id)}
                                >
                                  {copiedId === ev.id ? <CheckCircle2 size={10} color="#16a34a" /> : <Copy size={10} />}
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
