import React, { useState } from 'react';
import { Users, Clock, Globe, Server, Search, Calendar, ShieldCheck } from 'lucide-react';
import { UserBaseline, TrainingPeriodConfig } from '../types';
import { formatUtcDateTime } from '../utils/timestampNormalizer';

interface BaselineViewerProps {
  baselines: Map<string, UserBaseline>;
  trainingCutoff: string;
  trainingLogCount: number;
  totalEvaluationCount: number;
  trainingConfig: TrainingPeriodConfig;
}

export const BaselineViewer: React.FC<BaselineViewerProps> = ({
  baselines,
  trainingCutoff,
  trainingLogCount,
  totalEvaluationCount,
  trainingConfig
}) => {
  const [search, setSearch] = useState('');
  const baselineList = Array.from(baselines.values());

  const filtered = baselineList.filter(b => 
    b.user.toLowerCase().includes(search.toLowerCase()) ||
    b.usualHosts.some(h => h.toLowerCase().includes(search.toLowerCase())) ||
    b.usualIPs.some(ip => ip.includes(search))
  );

  return (
    <div>
      {/* Training Period Overview Card */}
      <div className="toolbar-card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--slate-900)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={16} />
              Declared Training Period &amp; Baseline Profiles
            </div>
            <div style={{ fontSize: 11, color: 'var(--slate-500)', marginTop: 2 }}>
              Learned from {trainingLogCount} historical authentication events &bull; Cutoff Timestamp: <strong>{formatUtcDateTime(trainingCutoff)}</strong>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontSize: 12 }}>
            <div style={{ background: '#f8fafc', padding: '6px 12px', borderRadius: 4, border: '1px solid #e2e8f0' }}>
              <span style={{ color: '#64748b' }}>Learned User Profiles:</span> <strong>{baselines.size}</strong>
            </div>
            <div style={{ background: '#f8fafc', padding: '6px 12px', borderRadius: 4, border: '1px solid #e2e8f0' }}>
              <span style={{ color: '#64748b' }}>Evaluation Log Volume:</span> <strong>{totalEvaluationCount}</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Search Bar */}
      <div style={{ marginBottom: 16, maxWidth: 350 }}>
        <div className="search-box">
          <Search size={14} className="search-icon" />
          <input
            type="text"
            className="search-input"
            placeholder="Search baseline by username, host, or IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Grid of User Baselines */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(440px, 1fr))', gap: 16 }}>
        {filtered.map(b => {
          // Calculate max hour count for chart scaling
          const maxHourCount = Math.max(1, ...Object.values(b.hourDistribution));

          return (
            <div key={b.user} className="detail-card" style={{ margin: 0 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid #e2e8f0', paddingBottom: 10, marginBottom: 12 }}>
                <div className="user-cell">
                  <div className="user-avatar" style={{ backgroundColor: '#0f172a', color: '#ffffff' }}>
                    {b.user.substring(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <div className="user-name" style={{ fontSize: 14 }}>{b.user}</div>
                    <div style={{ fontSize: 11, color: 'var(--slate-500)' }}>
                      {b.trainingLogsCount} baseline training events recorded
                    </div>
                  </div>
                </div>

                <span className="badge badge-low">
                  ACTIVE BASELINE
                </span>
              </div>

              {/* Diurnal Hour Distribution Histogram */}
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--slate-500)', textTransform: 'uppercase', marginBottom: 4, display: 'flex', justifyContent: 'space-between' }}>
                  <span>Usual Login Hours (00:00 - 23:00 UTC)</span>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>Habitual: {b.usualHours.map(h => `${h}h`).join(', ') || 'None'}</span>
                </div>

                <div className="hour-histogram">
                  {Array.from({ length: 24 }).map((_, hour) => {
                    const count = b.hourDistribution[hour] || 0;
                    const heightPct = count > 0 ? Math.max(15, (count / maxHourCount) * 100) : 4;
                    const isUsual = b.usualHours.includes(hour);

                    return (
                      <div key={hour} className="hour-col" title={`UTC ${hour.toString().padStart(2, '0')}:00 - ${count} events`}>
                        <div
                          className={`hour-bar ${isUsual ? 'active-hour' : ''}`}
                          style={{ height: `${heightPct}%` }}
                        />
                        <div className="hour-label">
                          {hour % 4 === 0 ? hour : ''}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Known IPs & Subnets */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 11 }}>
                <div style={{ backgroundColor: '#f8fafc', padding: 8, borderRadius: 4, border: '1px solid #e2e8f0' }}>
                  <div style={{ fontWeight: 600, color: '#475569', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Globe size={12} />
                    Habitual IPs / Subnets
                  </div>
                  <div className="mono" style={{ color: '#0f172a' }}>
                    {b.usualIPs.slice(0, 3).join(', ') || 'N/A'}
                    {b.usualIPs.length > 3 ? ` (+${b.usualIPs.length - 3} more)` : ''}
                  </div>
                  {b.usualSubnets.length > 0 && (
                    <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
                      Subnets: {b.usualSubnets.join(', ')}
                    </div>
                  )}
                </div>

                {/* Habitual Hosts */}
                <div style={{ backgroundColor: '#f8fafc', padding: 8, borderRadius: 4, border: '1px solid #e2e8f0' }}>
                  <div style={{ fontWeight: 600, color: '#475569', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Server size={12} />
                    Habitual Workstations / Hosts
                  </div>
                  <div className="mono" style={{ color: '#0f172a' }}>
                    {b.usualHosts.join(', ') || 'None'}
                  </div>
                  <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
                    Authorized assets for account
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
