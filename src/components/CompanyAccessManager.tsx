import React, { useState } from 'react';
import { 
  Building2, 
  ShieldCheck, 
  ShieldAlert, 
  Power, 
  Calendar, 
  Plus, 
  Users, 
  Globe, 
  Mail, 
  Clock,
  AlertTriangle,
  Lock,
  Unlock
} from 'lucide-react';
import { CompanyAccessConfig, CompanyStatus } from '../types';
import { formatUtcDateTime } from '../utils/timestampNormalizer';

interface CompanyAccessManagerProps {
  companies: CompanyAccessConfig[];
  setCompanies: React.Dispatch<React.SetStateAction<CompanyAccessConfig[]>>;
  selectedCompanyId: string;
  onSelectCompany: (id: string) => void;
}

export const CompanyAccessManager: React.FC<CompanyAccessManagerProps> = ({
  companies,
  setCompanies,
  selectedCompanyId,
  onSelectCompany
}) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [newCompany, setNewCompany] = useState<Partial<CompanyAccessConfig>>({
    name: '',
    code: '',
    status: 'ACTIVE',
    validUntil: '2027-12-31',
    contactEmail: '',
    maxSeats: 10,
    socAnalystAccess: true,
    allowedSubnets: ['10.0.0.0/16'],
    description: ''
  });

  const toggleCompanyStatus = (id: string) => {
    setCompanies(prev => prev.map(comp => {
      if (comp.id === id) {
        const nextStatus: CompanyStatus = comp.status === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE';
        return {
          ...comp,
          status: nextStatus,
          updatedAt: new Date().toISOString()
        };
      }
      return comp;
    }));
  };

  const updateValidUntil = (id: string, newDate: string) => {
    setCompanies(prev => prev.map(comp => {
      if (comp.id === id) {
        const isPast = new Date(newDate).getTime() < new Date().getTime();
        return {
          ...comp,
          validUntil: newDate,
          status: isPast ? 'EXPIRED' : comp.status,
          updatedAt: new Date().toISOString()
        };
      }
      return comp;
    }));
  };

  const handleAddCompany = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCompany.name || !newCompany.code) return;

    const id = `COMP-${(companies.length + 1).toString().padStart(3, '0')}`;
    const added: CompanyAccessConfig = {
      id,
      name: newCompany.name,
      code: newCompany.code.toUpperCase().replace(/\s+/g, '-'),
      status: newCompany.status || 'ACTIVE',
      validUntil: newCompany.validUntil || '2027-12-31',
      contactEmail: newCompany.contactEmail || 'admin@example.com',
      maxSeats: newCompany.maxSeats || 10,
      socAnalystAccess: true,
      allowedSubnets: newCompany.allowedSubnets || ['10.0.0.0/16'],
      description: newCompany.description || 'Enterprise tenant profile',
      updatedAt: new Date().toISOString()
    };

    setCompanies(prev => [...prev, added]);
    setShowAddModal(false);
    setNewCompany({
      name: '',
      code: '',
      status: 'ACTIVE',
      validUntil: '2027-12-31',
      contactEmail: '',
      maxSeats: 10,
      socAnalystAccess: true,
      allowedSubnets: ['10.0.0.0/16'],
      description: ''
    });
  };

  return (
    <div>
      {/* Top Banner */}
      <div className="toolbar-card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--slate-900)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Building2 size={16} />
              Enterprise Multi-Tenant Access Control &amp; Authorization
            </div>
            <div style={{ fontSize: 11, color: 'var(--slate-500)', marginTop: 2 }}>
              Manage authorized client organizations, define access validity expiry dates, and immediately revoke access when needed.
            </div>
          </div>

          <button className="btn btn-primary btn-sm" onClick={() => setShowAddModal(true)}>
            <Plus size={13} />
            Add Client Organization
          </button>
        </div>
      </div>

      {/* Grid of Companies */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(480px, 1fr))', gap: 16 }}>
        {companies.map((comp) => {
          const isSelected = comp.id === selectedCompanyId;
          const isExpired = new Date(comp.validUntil).getTime() < new Date().getTime();
          const effectiveStatus: CompanyStatus = isExpired ? 'EXPIRED' : comp.status;
          const isActive = effectiveStatus === 'ACTIVE';

          return (
            <div
              key={comp.id}
              className="detail-card"
              style={{
                margin: 0,
                border: isSelected ? '2px solid var(--slate-900)' : '1px solid var(--border-subtle)',
                backgroundColor: !isActive ? '#fffdfd' : '#ffffff'
              }}
            >
              {/* Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--slate-900)' }}>
                      {comp.name}
                    </span>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--slate-600)', background: '#f1f5f9', padding: '1px 6px', borderRadius: 3 }}>
                      {comp.code}
                    </span>
                    {isSelected && (
                      <span className="badge" style={{ backgroundColor: '#0f172a', color: '#ffffff' }}>
                        CURRENT TENANT
                      </span>
                    )}
                  </div>
                  <p style={{ fontSize: 12, color: 'var(--slate-600)', marginTop: 4 }}>
                    {comp.description}
                  </p>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {effectiveStatus === 'ACTIVE' && (
                    <span className="badge" style={{ backgroundColor: '#f0fdf4', color: '#166534', border: '1px solid #bbf7d0' }}>
                      ACTIVE ACCESS
                    </span>
                  )}
                  {effectiveStatus === 'SUSPENDED' && (
                    <span className="badge" style={{ backgroundColor: '#fef2f2', color: '#991b1b', border: '1px solid #fecaca' }}>
                      ACCESS REVOKED
                    </span>
                  )}
                  {effectiveStatus === 'EXPIRED' && (
                    <span className="badge" style={{ backgroundColor: '#fffbeb', color: '#b45309', border: '1px solid #fde68a' }}>
                      CONTRACT EXPIRED
                    </span>
                  )}
                </div>
              </div>

              {/* Enterprise Settings Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 11, marginBottom: 14, backgroundColor: '#f8fafc', padding: 10, borderRadius: 4, border: '1px solid #e2e8f0' }}>
                <div>
                  <span style={{ color: '#64748b', display: 'flex', alignItems: 'center', gap: 4, marginBottom: 2 }}>
                    <Calendar size={12} />
                    Valid Access Until (Turn-off Date):
                  </span>
                  <input
                    type="date"
                    className="search-input"
                    style={{ fontSize: 11, padding: '3px 6px', width: '100%' }}
                    value={comp.validUntil.slice(0, 10)}
                    onChange={(e) => updateValidUntil(comp.id, e.target.value)}
                  />
                </div>

                <div>
                  <span style={{ color: '#64748b', display: 'flex', alignItems: 'center', gap: 4, marginBottom: 2 }}>
                    <Users size={12} />
                    Authorized SOC Analyst Seats:
                  </span>
                  <div style={{ fontWeight: 600, color: 'var(--slate-800)', marginTop: 5 }}>
                    {comp.maxSeats} Assigned Seats
                  </div>
                </div>

                <div>
                  <span style={{ color: '#64748b', display: 'flex', alignItems: 'center', gap: 4, marginBottom: 2 }}>
                    <Mail size={12} />
                    Designated Security Contact:
                  </span>
                  <div className="mono" style={{ color: 'var(--slate-800)' }}>
                    {comp.contactEmail}
                  </div>
                </div>

                <div>
                  <span style={{ color: '#64748b', display: 'flex', alignItems: 'center', gap: 4, marginBottom: 2 }}>
                    <Globe size={12} />
                    Allowed CIDR Subnets:
                  </span>
                  <div className="mono" style={{ color: 'var(--slate-800)' }}>
                    {comp.allowedSubnets.join(', ') || 'Any'}
                  </div>
                </div>
              </div>

              {/* Actions Footer */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid #e2e8f0', paddingTop: 10 }}>
                <div>
                  {!isSelected && (
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => onSelectCompany(comp.id)}
                    >
                      Switch Active Tenant
                    </button>
                  )}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {isActive ? (
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => toggleCompanyStatus(comp.id)}
                      title="Instantly revoke tenant access and lock out users"
                    >
                      <Lock size={12} />
                      Turn Access Off (Suspend)
                    </button>
                  ) : (
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => toggleCompanyStatus(comp.id)}
                      title="Restore enterprise access"
                    >
                      <Unlock size={12} />
                      Turn Access On (Activate)
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Add Company Modal */}
      {showAddModal && (
        <div className="modal-overlay" onClick={() => setShowAddModal(false)}>
          <div className="modal-content" style={{ maxWidth: 550 }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">Provision New Client Organization</div>
              <button className="btn-close" onClick={() => setShowAddModal(false)}>
                &times;
              </button>
            </div>
            <form onSubmit={handleAddCompany}>
              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div>
                  <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                    Company Name
                  </label>
                  <input
                    type="text"
                    required
                    className="search-input"
                    placeholder="e.g. Acme Defense Cyber Ltd"
                    value={newCompany.name}
                    onChange={(e) => setNewCompany(p => ({ ...p, name: e.target.value }))}
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                      Company Code
                    </label>
                    <input
                      type="text"
                      required
                      className="search-input"
                      placeholder="e.g. ACME-DEF"
                      value={newCompany.code}
                      onChange={(e) => setNewCompany(p => ({ ...p, code: e.target.value }))}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                      Initial Status
                    </label>
                    <select
                      className="filter-select"
                      style={{ width: '100%' }}
                      value={newCompany.status}
                      onChange={(e) => setNewCompany(p => ({ ...p, status: e.target.value as any }))}
                    >
                      <option value="ACTIVE">ACTIVE</option>
                      <option value="SUSPENDED">SUSPENDED</option>
                    </select>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                      Access Valid Until
                    </label>
                    <input
                      type="date"
                      required
                      className="search-input"
                      value={newCompany.validUntil}
                      onChange={(e) => setNewCompany(p => ({ ...p, validUntil: e.target.value }))}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                      Max SOC Analyst Seats
                    </label>
                    <input
                      type="number"
                      min={1}
                      max={100}
                      className="search-input"
                      value={newCompany.maxSeats}
                      onChange={(e) => setNewCompany(p => ({ ...p, maxSeats: Number(e.target.value) }))}
                    />
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                    Designated Security Contact Email
                  </label>
                  <input
                    type="email"
                    required
                    className="search-input"
                    placeholder="soc-lead@company.example.com"
                    value={newCompany.contactEmail}
                    onChange={(e) => setNewCompany(p => ({ ...p, contactEmail: e.target.value }))}
                  />
                </div>

                <div>
                  <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                    Description &amp; Operational Scope
                  </label>
                  <textarea
                    className="search-input"
                    style={{ height: 60, resize: 'none' }}
                    placeholder="Tier-1 monitoring scope, regulatory compliance requirements..."
                    value={newCompany.description}
                    onChange={(e) => setNewCompany(p => ({ ...p, description: e.target.value }))}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowAddModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Provision Tenant
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
