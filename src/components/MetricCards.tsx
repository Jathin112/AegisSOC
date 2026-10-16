import React from 'react';
import { 
  Database, 
  CopyX, 
  AlertOctagon, 
  ShieldCheck, 
  Activity,
  Flame
} from 'lucide-react';
import { UserIncident } from '../types';

interface MetricCardsProps {
  totalLogs: number;
  duplicateCount: number;
  uniqueLogsCount: number;
  incidents: UserIncident[];
}

export const MetricCards: React.FC<MetricCardsProps> = ({
  totalLogs,
  duplicateCount,
  uniqueLogsCount,
  incidents
}) => {
  const criticalCount = incidents.filter(i => i.severity === 'CRITICAL').length;
  const highCount = incidents.filter(i => i.severity === 'HIGH').length;
  const confirmedCompromises = incidents.filter(i => i.threatClass === 'CONFIRMED_COMPROMISE').length;
  const suspiciousIndications = incidents.filter(i => i.threatClass === 'SUSPICIOUS').length;

  const avgRiskScore = incidents.length > 0
    ? Math.round(incidents.reduce((acc, i) => acc + i.riskScore, 0) / incidents.length)
    : 0;

  return (
    <div className="metrics-grid">
      <div className="metric-card">
        <div className="metric-top">
          <span className="metric-label">Ingested Logs</span>
          <div className="metric-icon-box">
            <Database size={15} />
          </div>
        </div>
        <div className="metric-value">{totalLogs.toLocaleString()}</div>
        <div className="metric-sub">
          <span>{uniqueLogsCount.toLocaleString()} unique canonical records</span>
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-top">
          <span className="metric-label">Deduplicated</span>
          <div className="metric-icon-box">
            <CopyX size={15} />
          </div>
        </div>
        <div className="metric-value">{duplicateCount}</div>
        <div className="metric-sub">
          <span>{totalLogs > 0 ? ((duplicateCount / totalLogs) * 100).toFixed(1) : 0}% duplicate suppression rate</span>
        </div>
      </div>

      <div className={`metric-card ${criticalCount > 0 ? 'critical' : highCount > 0 ? 'high' : ''}`}>
        <div className="metric-top">
          <span className="metric-label">Active Incidents</span>
          <div className="metric-icon-box">
            <AlertOctagon size={15} />
          </div>
        </div>
        <div className="metric-value">{incidents.length}</div>
        <div className="metric-sub">
          <span><strong>{criticalCount}</strong> Critical &bull; <strong>{highCount}</strong> High Priority</span>
        </div>
      </div>

      <div className={`metric-card ${confirmedCompromises > 0 ? 'critical' : ''}`}>
        <div className="metric-top">
          <span className="metric-label">Threat Classification</span>
          <div className="metric-icon-box">
            {confirmedCompromises > 0 ? <Flame size={15} /> : <ShieldCheck size={15} />}
          </div>
        </div>
        <div className="metric-value">{confirmedCompromises}</div>
        <div className="metric-sub">
          <span>Confirmed Compromise ({suspiciousIndications} Suspicious)</span>
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-top">
          <span className="metric-label">Average Risk Score</span>
          <div className="metric-icon-box">
            <Activity size={15} />
          </div>
        </div>
        <div className="metric-value">{avgRiskScore}<span style={{ fontSize: 14, color: 'var(--slate-500)' }}>/100</span></div>
        <div className="metric-sub">
          <span>Targeting {new Set(incidents.map(i => i.user)).size} enterprise accounts</span>
        </div>
      </div>
    </div>
  );
};
