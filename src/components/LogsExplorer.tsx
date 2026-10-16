import React, { useState } from 'react';
import { Database, Search, Filter, Copy, CheckCircle2, Layers } from 'lucide-react';
import { NormalizedAuthLog } from '../types';
import { formatUtcDateTime } from '../utils/timestampNormalizer';

interface LogsExplorerProps {
  logs: NormalizedAuthLog[];
}

export const LogsExplorer: React.FC<LogsExplorerProps> = ({ logs }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState<'ALL' | 'SUCCESS' | 'FAILURE'>('ALL');
  const [periodFilter, setPeriodFilter] = useState<'ALL' | 'TRAINING' | 'EVALUATION'>('ALL');
  const [showDuplicatesOnly, setShowDuplicatesOnly] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const pageSize = 50;

  const filteredLogs = logs.filter(log => {
    if (actionFilter !== 'ALL' && log.action !== actionFilter) return false;
    if (periodFilter === 'TRAINING' && !log.inTrainingPeriod) return false;
    if (periodFilter === 'EVALUATION' && log.inTrainingPeriod) return false;
    if (showDuplicatesOnly && !log.isDuplicate && (log.duplicateCount || 1) <= 1) return false;

    if (!searchTerm) return true;
    const q = searchTerm.toLowerCase();
    return (
      log.user.toLowerCase().includes(q) ||
      log.ip.includes(q) ||
      log.host.toLowerCase().includes(q) ||
      log.failureReason.toLowerCase().includes(q) ||
      log.location.toLowerCase().includes(q) ||
      log.hash.toLowerCase().includes(q)
    );
  });

  const totalPages = Math.ceil(filteredLogs.length / pageSize) || 1;
  const currentLogs = filteredLogs.slice((page - 1) * pageSize, page * pageSize);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div>
      {/* Top filter bar */}
      <div className="toolbar-card" style={{ marginBottom: 16 }}>
        <div className="toolbar-primary">
          <div className="search-box">
            <Search size={14} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Filter logs by user, IP, host, hash, reason, or location..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(1);
              }}
            />
          </div>

          <div className="filter-group">
            <select
              className="filter-select"
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value as any);
                setPage(1);
              }}
            >
              <option value="ALL">All Actions (Success &amp; Failure)</option>
              <option value="SUCCESS">Success Only</option>
              <option value="FAILURE">Failure Only</option>
            </select>

            <select
              className="filter-select"
              value={periodFilter}
              onChange={(e) => {
                setPeriodFilter(e.target.value as any);
                setPage(1);
              }}
            >
              <option value="ALL">All Data Windows</option>
              <option value="TRAINING">Training Baseline Logs Only</option>
              <option value="EVALUATION">Evaluation (Post-Baseline) Only</option>
            </select>

            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, cursor: 'pointer', background: '#f8fafc', padding: '5px 8px', borderRadius: 4, border: '1px solid #cbd5e1' }}>
              <input
                type="checkbox"
                checked={showDuplicatesOnly}
                onChange={(e) => {
                  setShowDuplicatesOnly(e.target.checked);
                  setPage(1);
                }}
              />
              <span style={{ fontWeight: 600, color: '#475569' }}>Show Duplicates Only</span>
            </label>
          </div>
        </div>
      </div>

      {/* Info bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10, fontSize: 11, color: 'var(--slate-500)' }}>
        <div>
          Showing <strong>{(page - 1) * pageSize + 1}</strong> &ndash; <strong>{Math.min(page * pageSize, filteredLogs.length)}</strong> of <strong>{filteredLogs.length}</strong> matching records (Total dataset: {logs.length})
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <button 
            className="btn btn-secondary btn-sm"
            disabled={page <= 1}
            onClick={() => setPage(p => Math.max(1, p - 1))}
          >
            Previous
          </button>
          <span>Page {page} of {totalPages}</span>
          <button 
            className="btn btn-secondary btn-sm"
            disabled={page >= totalPages}
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
          >
            Next
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="table-container">
        <table className="soc-table">
          <thead>
            <tr>
              <th style={{ width: 140 }}>Normalized UTC Time</th>
              <th>Target User</th>
              <th>Source IP</th>
              <th>Target Host</th>
              <th>Action</th>
              <th>Reason / Details</th>
              <th>Network Location</th>
              <th>Data Window</th>
              <th>Deduplication Hash</th>
              <th style={{ width: 40 }}></th>
            </tr>
          </thead>
          <tbody>
            {currentLogs.map((log) => {
              const isFailure = log.action === 'FAILURE';

              return (
                <tr key={log.id} style={{ backgroundColor: log.isDuplicate ? '#fefce8' : undefined }}>
                  <td className="mono">{formatUtcDateTime(log.timestamp)}</td>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--slate-900)' }}>{log.user}</div>
                  </td>
                  <td className="mono">{log.ip}</td>
                  <td className="mono">{log.host}</td>
                  <td>
                    <span
                      className="badge"
                      style={{
                        backgroundColor: isFailure ? '#fef2f2' : '#f0fdf4',
                        color: isFailure ? '#991b1b' : '#166534',
                        border: `1px solid ${isFailure ? '#fecaca' : '#bbf7d0'}`
                      }}
                    >
                      {log.action}
                    </span>
                  </td>
                  <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={log.failureReason}>
                    {log.failureReason}
                  </td>
                  <td style={{ color: 'var(--slate-600)' }}>{log.location}</td>
                  <td>
                    {log.inTrainingPeriod ? (
                      <span className="badge" style={{ backgroundColor: '#f1f5f9', color: '#475569', border: '1px solid #cbd5e1' }}>
                        TRAINING
                      </span>
                    ) : (
                      <span className="badge" style={{ backgroundColor: '#f8fafc', color: '#0f172a', border: '1px solid #94a3b8' }}>
                        EVALUATION
                      </span>
                    )}
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span className="mono" style={{ fontSize: 10, color: 'var(--slate-500)' }}>{log.hash}</span>
                      {(log.duplicateCount || 1) > 1 && (
                        <span 
                          className="badge" 
                          style={{ backgroundColor: '#fef3c7', color: '#92400e', border: '1px solid #fde68a', fontSize: 9 }}
                          title={`Occurred ${log.duplicateCount} times identically`}
                        >
                          x{log.duplicateCount}
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <button
                      className="btn btn-secondary btn-sm"
                      style={{ padding: '2px 5px', fontSize: 10 }}
                      onClick={() => handleCopy(`${log.timestamp},${log.user},${log.ip},${log.host},${log.action},${log.failureReason}`, log.id)}
                      title="Copy log row"
                    >
                      {copiedId === log.id ? <CheckCircle2 size={11} color="#16a34a" /> : <Copy size={11} />}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
