import React from 'react';
import { ShieldAlert, TrendingUp, CheckCircle, Flame, Layers } from 'lucide-react';
import { RiskScoreContribution } from '../types';

interface RiskScoreBreakdownCardProps {
  score: number;
  isCompromise: boolean;
  isContextSuppressed: boolean;
  breakdown: RiskScoreContribution[];
}

export const RiskScoreBreakdownCard: React.FC<RiskScoreBreakdownCardProps> = ({
  score,
  isCompromise,
  isContextSuppressed,
  breakdown
}) => {
  return (
    <div className="detail-card">
      <div className="detail-card-title" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Layers size={15} />
          <span>Risk Score Formula &amp; Detection Rule Breakdown</span>
        </div>
        <span 
          style={{ 
            fontSize: 12, 
            fontWeight: 700, 
            color: isCompromise ? '#991b1b' : score >= 60 ? '#c2410c' : '#166534',
            backgroundColor: isCompromise ? '#fef2f2' : score >= 60 ? '#fff7ed' : '#f0fdf4',
            padding: '2px 8px',
            borderRadius: 4,
            border: `1px solid ${isCompromise ? '#fecaca' : score >= 60 ? '#fed7aa' : '#bbf7d0'}`
          }}
        >
          Final Score: {score}/100
        </span>
      </div>

      <div style={{ fontSize: 11, color: 'var(--slate-600)', marginBottom: 12 }}>
        Transparent mathematical calculation showing rule weights, compounding multi-vector bonuses, and contextual mitigations applied.
      </div>

      {/* Visual Stacked Contribution Meter */}
      <div style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--slate-500)', marginBottom: 4 }}>
          <span>Risk Factor Proportions</span>
          <span>Max Theoretical Score: 100</span>
        </div>
        <div 
          style={{ 
            height: 12, 
            backgroundColor: '#e2e8f0', 
            borderRadius: 6, 
            overflow: 'hidden', 
            display: 'flex',
            boxShadow: 'inset 0 1px 2px rgba(0,0,0,0.06)'
          }}
        >
          {breakdown.filter(b => b.pointsAdded > 0).map((b, i) => {
            const colors = ['#dc2626', '#ea580c', '#d97706', '#0284c7', '#7c3aed', '#475569'];
            const color = colors[i % colors.length];
            return (
              <div 
                key={b.ruleId} 
                title={`${b.ruleName}: +${b.pointsAdded} pts (${b.percentageOfTotal}%)`}
                style={{ 
                  width: `${b.percentageOfTotal}%`, 
                  backgroundColor: color,
                  transition: 'width 0.3s ease'
                }} 
              />
            );
          })}
        </div>
      </div>

      {/* Itemized Breakdown Table */}
      <div style={{ overflowX: 'auto', border: '1px solid #e2e8f0', borderRadius: 4 }}>
        <table className="soc-table" style={{ fontSize: 11 }}>
          <thead>
            <tr>
              <th>Rule / Factor</th>
              <th>Category</th>
              <th style={{ textAlign: 'right' }}>Score Impact</th>
              <th style={{ textAlign: 'right' }}>% Total</th>
              <th>Forensic Rationale</th>
            </tr>
          </thead>
          <tbody>
            {breakdown.map((item, idx) => {
              const isDiscount = item.pointsAdded < 0;
              return (
                <tr key={`${item.ruleId}-${idx}`} style={{ backgroundColor: isDiscount ? '#f0fdf4' : undefined }}>
                  <td style={{ fontWeight: 600, color: isDiscount ? '#166534' : 'var(--slate-800)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {isDiscount ? (
                        <CheckCircle size={13} color="#16a34a" />
                      ) : item.pointsAdded >= 35 ? (
                        <Flame size={13} color="#dc2626" />
                      ) : (
                        <TrendingUp size={13} color="#ea580c" />
                      )}
                      {item.ruleName}
                    </div>
                  </td>
                  <td>
                    <span 
                      className="badge" 
                      style={{ 
                        fontSize: 9, 
                        padding: '1px 5px',
                        backgroundColor: '#f1f5f9',
                        color: '#475569'
                      }}
                    >
                      {item.category}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right', fontWeight: 700, fontFamily: 'monospace' }}>
                    <span style={{ color: isDiscount ? '#16a34a' : item.pointsAdded >= 30 ? '#dc2626' : '#d97706' }}>
                      {item.pointsAdded > 0 ? `+${item.pointsAdded}` : item.pointsAdded} pts
                    </span>
                  </td>
                  <td style={{ textAlign: 'right', color: 'var(--slate-500)', fontFamily: 'monospace' }}>
                    {isDiscount ? 'Mitigation' : `${item.percentageOfTotal}%`}
                  </td>
                  <td style={{ color: 'var(--slate-600)', fontSize: 11 }}>
                    {item.reason}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Summary Formula Callout */}
      <div 
        style={{ 
          marginTop: 10, 
          padding: '8px 12px', 
          backgroundColor: '#f8fafc', 
          borderRadius: 4, 
          fontSize: 11, 
          border: '1px solid #e2e8f0',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}
      >
        <span style={{ color: 'var(--slate-600)' }}>
          <strong>Calculation Formula:</strong> Base Rule Points + Multi-Vector Multiplier + Evidence Volume Bonus &minus; Context Mitigations
        </span>
        <span style={{ fontWeight: 700, color: 'var(--slate-800)', fontFamily: 'monospace' }}>
          Net Calculated: {score}/100
        </span>
      </div>
    </div>
  );
};
