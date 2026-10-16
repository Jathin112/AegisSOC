import React from 'react';
import { Search, Filter, RotateCcw, Calendar, SlidersHorizontal } from 'lucide-react';
import { FilterState, TrainingPeriodConfig } from '../types';

interface FilterBarProps {
  filters: FilterState;
  setFilters: React.Dispatch<React.SetStateAction<FilterState>>;
  trainingConfig: TrainingPeriodConfig;
  setTrainingConfig: React.Dispatch<React.SetStateAction<TrainingPeriodConfig>>;
  onResetFilters: () => void;
  uniqueUsers: string[];
  uniqueHosts: string[];
}

export const FilterBar: React.FC<FilterBarProps> = ({
  filters,
  setFilters,
  trainingConfig,
  setTrainingConfig,
  onResetFilters,
  uniqueUsers,
  uniqueHosts
}) => {
  return (
    <div className="toolbar-card">
      <div className="toolbar-primary">
        <div className="search-box">
          <Search size={14} className="search-icon" />
          <input
            type="text"
            className="search-input"
            placeholder="Search by User, Host, IP, or Rule category..."
            value={filters.searchQuery}
            onChange={(e) => setFilters(prev => ({ ...prev, searchQuery: e.target.value }))}
          />
        </div>

        <div className="filter-group">
          {/* Severity */}
          <select
            className="filter-select"
            value={filters.severity}
            onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value as any }))}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Threat Class */}
          <select
            className="filter-select"
            value={filters.threatClass}
            onChange={(e) => setFilters(prev => ({ ...prev, threatClass: e.target.value as any }))}
          >
            <option value="ALL">All Threat Classes</option>
            <option value="CONFIRMED_COMPROMISE">Confirmed Compromise</option>
            <option value="SUSPICIOUS">Suspicious Indication</option>
          </select>

          {/* Rule Category */}
          <select
            className="filter-select"
            value={filters.ruleCategory}
            onChange={(e) => setFilters(prev => ({ ...prev, ruleCategory: e.target.value as any }))}
          >
            <option value="ALL">All Detection Rules</option>
            <option value="BURST_FAILURE_THEN_SUCCESS">Burst Failure &rarr; Success</option>
            <option value="REPEATED_FAILURES">Repeated Failures (Brute Force)</option>
            <option value="PASSWORD_SPRAY">Password Spraying</option>
            <option value="HOST_EXPANSION">Host Access Expansion</option>
            <option value="UNUSUAL_TIME">Unusual Login Time</option>
            <option value="UNFAMILIAR_IP">Unfamiliar IP/Subnet</option>
          </select>

          {/* Status */}
          <select
            className="filter-select"
            value={filters.status}
            onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value as any }))}
          >
            <option value="ALL">All Incident Statuses</option>
            <option value="NEW">New</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="ESCALATED">Escalated</option>
            <option value="REMEDIATED">Remediated</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>

          {/* User filter */}
          {uniqueUsers.length > 0 && (
            <select
              className="filter-select"
              value={filters.user}
              onChange={(e) => setFilters(prev => ({ ...prev, user: e.target.value }))}
            >
              <option value="">All Users ({uniqueUsers.length})</option>
              {uniqueUsers.map(u => (
                <option key={u} value={u}>{u}</option>
              ))}
            </select>
          )}

          {/* Host filter */}
          {uniqueHosts.length > 0 && (
            <select
              className="filter-select"
              value={filters.host}
              onChange={(e) => setFilters(prev => ({ ...prev, host: e.target.value }))}
            >
              <option value="">All Hosts ({uniqueHosts.length})</option>
              {uniqueHosts.map(h => (
                <option key={h} value={h}>{h}</option>
              ))}
            </select>
          )}

          {/* Training Period Window Tuner */}
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: '#f8fafc', padding: '3px 8px', borderRadius: 4, border: '1px solid #cbd5e1' }}>
            <Calendar size={13} style={{ color: '#64748b' }} />
            <span style={{ fontSize: 11, fontWeight: 600, color: '#475569' }}>Baseline Training:</span>
            <select
              className="filter-select"
              style={{ padding: '2px 6px', fontSize: 11 }}
              value={trainingConfig.percentage || 50}
              onChange={(e) => setTrainingConfig(prev => ({ ...prev, mode: 'PERCENTAGE', percentage: Number(e.target.value) }))}
            >
              <option value={30}>First 30% of Logs</option>
              <option value={40}>First 40% of Logs</option>
              <option value={50}>First 50% of Logs (Standard)</option>
              <option value={60}>First 60% of Logs</option>
              <option value={75}>First 75% of Logs</option>
            </select>
          </div>

          <button
            className="btn btn-secondary btn-sm"
            onClick={onResetFilters}
            title="Clear all active filters"
          >
            <RotateCcw size={12} />
            Reset
          </button>
        </div>
      </div>
    </div>
  );
};
