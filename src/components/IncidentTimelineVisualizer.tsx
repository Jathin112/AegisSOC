import React, { useState } from 'react';
import { 
  Clock, 
  ShieldAlert, 
  XCircle, 
  CheckCircle2, 
  Filter, 
  Search, 
  Copy, 
  Flame, 
  ChevronRight,
  ExternalLink 
} from 'lucide-react';
import { IncidentTimelineEvent, UserIncident } from '../types';
import { formatUtcDateTime } from '../utils/timestampNormalizer';

interface IncidentTimelineVisualizerProps {
  events: IncidentTimelineEvent[];
  incident: UserIncident;
}

export const IncidentTimelineVisualizer: React.FC<IncidentTimelineVisualizerProps> = ({
  events,
  incident
}) => {
  const [filterType, setFilterType] = useState<'ALL' | 'ALERTS_ONLY' | 'FAILURES_ONLY' | 'SUCCESSES_ONLY'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredEvents = events.filter(ev => {
    // Type filter
    if (filterType === 'ALERTS_ONLY' && ev.type !== 'DETECTION_ALERT') return false;
    if (filterType === 'FAILURES_ONLY' && ev.type !== 'AUTH_FAILURE') return false;
    if (filterType === 'SUCCESSES_ONLY' && ev.type !== 'AUTH_SUCCESS') return false;

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = ev.title.toLowerCase().includes(q);
      const matchDesc = ev.description.toLowerCase().includes(q);
      const matchHost = ev.host?.toLowerCase().includes(q);
      const matchIp = ev.ip?.toLowerCase().includes(q);
      const matchReason = ev.failureReason?.toLowerCase().includes(q);
      return matchTitle || matchDesc || matchHost || matchIp || matchReason;
    }
    return true;
  });

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const alertCount = events.filter(e => e.type === 'DETECTION_ALERT').length;
  const failureCount = events.filter(e => e.type === 'AUTH_FAILURE').length;
  const successCount = events.filter(e => e.type === 'AUTH_SUCCESS').length;

  return (
    <div className="detail-card">
      <div className="detail-card-title" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Clock size={15} />
          <span>Chronological Incident &amp; Attack Progression Timeline</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
          <span className="badge" style={{ backgroundColor: '#fef2f2', color: '#991b1b', border: '1px solid #fecaca' }}>
            {alertCount} Alerts
          </span>
          <span className="badge" style={{ backgroundColor: '#fff7ed', color: '#c2410c', border: '1px solid #fed7aa' }}>
            {failureCount} Failures
          </span>
          <span className="badge" style={{ backgroundColor: '#f0fdf4', color: '#166534', border: '1px solid #bbf7d0' }}>
            {successCount} Successes
          </span>
        </div>
      </div>

      <div style={{ fontSize: 11, color: 'var(--slate-600)', marginBottom: 12 }}>
        Interactive chronological sequence plotting suspicious authentication attempts alongside correlated SOC detection alert triggers.
      </div>

      {/* Filter and Search Bar */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: 4 }}>
          <button
            className={`btn btn-sm ${filterType === 'ALL' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setFilterType('ALL')}
            style={{ fontSize: 11, padding: '4px 8px' }}
          >
            All Events ({events.length})
          </button>
          <button
            className={`btn btn-sm ${filterType === 'ALERTS_ONLY' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setFilterType('ALERTS_ONLY')}
            style={{ fontSize: 11, padding: '4px 8px' }}
          >
            Alerts Only ({alertCount})
          </button>
          <button
            className={`btn btn-sm ${filterType === 'FAILURES_ONLY' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setFilterType('FAILURES_ONLY')}
            style={{ fontSize: 11, padding: '4px 8px' }}
          >
            Failures ({failureCount})
          </button>
          <button
            className={`btn btn-sm ${filterType === 'SUCCESSES_ONLY' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setFilterType('SUCCESSES_ONLY')}
            style={{ fontSize: 11, padding: '4px 8px' }}
          >
            Successes ({successCount})
          </button>
        </div>

        <div style={{ flex: 1, minWidth: 180, display: 'flex', alignItems: 'center', position: 'relative' }}>
          <Search size={13} style={{ position: 'absolute', left: 8, color: 'var(--slate-400)' }} />
          <input
            type="text"
            className="filter-input"
            placeholder="Search timeline events, hosts, IPs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ width: '100%', paddingLeft: 26, fontSize: 11 }}
          />
        </div>
      </div>

      {/* Timeline Stream */}
      <div style={{ position: 'relative', paddingLeft: 24, borderLeft: '2px solid #e2e8f0', marginLeft: 8 }}>
        {filteredEvents.length === 0 ? (
          <div style={{ padding: '16px 0', fontSize: 12, color: 'var(--slate-500)', fontStyle: 'italic' }}>
            No timeline events match the current filter.
          </div>
        ) : (
          filteredEvents.map((ev, index) => {
            const isAlert = ev.type === 'DETECTION_ALERT';
            const isSuccess = ev.type === 'AUTH_SUCCESS';
            const isFailure = ev.type === 'AUTH_FAILURE';

            return (
              <div 
                key={ev.id} 
                style={{ 
                  position: 'relative', 
                  marginBottom: 16,
                  paddingBottom: index === filteredEvents.length - 1 ? 0 : 4
                }}
              >
                {/* Visual Timeline Marker Node */}
                <div 
                  style={{
                    position: 'absolute',
                    left: -33,
                    top: 2,
                    width: 18,
                    height: 18,
                    borderRadius: '50%',
                    backgroundColor: isAlert ? '#dc2626' : isSuccess ? '#16a34a' : '#ea580c',
                    color: '#ffffff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: '3px solid #ffffff',
                    boxShadow: '0 0 0 1px #cbd5e1'
                  }}
                >
                  {isAlert ? (
                    <ShieldAlert size={10} />
                  ) : isSuccess ? (
                    <CheckCircle2 size={10} />
                  ) : (
                    <XCircle size={10} />
                  )}
                </div>

                {/* Event Card */}
                <div 
                  style={{
                    backgroundColor: isAlert ? '#fef2f2' : isSuccess ? '#f0fdf4' : '#ffffff',
                    border: `1px solid ${isAlert ? '#fecaca' : isSuccess ? '#bbf7d0' : '#e2e8f0'}`,
                    borderRadius: 4,
                    padding: '8px 12px',
                    fontSize: 11,
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                      <span 
                        style={{ 
                          fontWeight: 700, 
                          color: isAlert ? '#991b1b' : isSuccess ? '#166534' : 'var(--slate-800)' 
                        }}
                      >
                        {ev.title}
                      </span>

                      {isAlert && (
                        <span 
                          className="badge" 
                          style={{ 
                            fontSize: 9, 
                            padding: '1px 5px', 
                            backgroundColor: '#991b1b', 
                            color: '#ffffff' 
                          }}
                        >
                          SOC ALERT
                        </span>
                      )}

                      {ev.confidence && (
                        <span 
                          className="badge" 
                          style={{ 
                            fontSize: 9, 
                            padding: '1px 5px', 
                            backgroundColor: '#fef3c7', 
                            color: '#92400e', 
                            border: '1px solid #fde68a' 
                          }}
                        >
                          {ev.confidence} CONFIDENCE
                        </span>
                      )}

                      {ev.host && (
                        <span className="mono" style={{ fontSize: 10, backgroundColor: '#f1f5f9', padding: '1px 4px', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                          Host: {ev.host}
                        </span>
                      )}

                      {ev.ip && (
                        <span className="mono" style={{ fontSize: 10, backgroundColor: '#f1f5f9', padding: '1px 4px', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                          IP: {ev.ip}
                        </span>
                      )}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 10, color: 'var(--slate-500)', fontFamily: 'monospace' }}>
                        {formatUtcDateTime(ev.timestamp)}
                      </span>
                      <button
                        className="btn btn-secondary btn-sm"
                        style={{ padding: '2px 5px', fontSize: 9 }}
                        onClick={() => handleCopy(`${ev.timestamp} | ${ev.title} | ${ev.description}`, ev.id)}
                        title="Copy event payload"
                      >
                        {copiedId === ev.id ? <CheckCircle2 size={10} color="#16a34a" /> : <Copy size={10} />}
                      </button>
                    </div>
                  </div>

                  <div style={{ color: isAlert ? '#7f1d1d' : 'var(--slate-600)', lineHeight: 1.4 }}>
                    {ev.description}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
