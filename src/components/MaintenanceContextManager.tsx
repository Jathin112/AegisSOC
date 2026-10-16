import React, { useState } from 'react';
import { 
  Calendar, 
  ShieldCheck, 
  Globe, 
  Users, 
  Plus, 
  CheckCircle2, 
  Clock, 
  AlertTriangle,
  Briefcase,
  Laptop,
  Ticket
} from 'lucide-react';
import { MaintenanceWindow, UserAccountConfig, CompanyVpnConfig, AccountRole } from '../types';
import { formatUtcDateTime } from '../utils/timestampNormalizer';

interface MaintenanceContextManagerProps {
  maintenanceWindows: MaintenanceWindow[];
  setMaintenanceWindows: React.Dispatch<React.SetStateAction<MaintenanceWindow[]>>;
  userAccounts: UserAccountConfig[];
  setUserAccounts: React.Dispatch<React.SetStateAction<UserAccountConfig[]>>;
  vpnConfigs: CompanyVpnConfig[];
  setVpnConfigs: React.Dispatch<React.SetStateAction<CompanyVpnConfig[]>>;
}

export const MaintenanceContextManager: React.FC<MaintenanceContextManagerProps> = ({
  maintenanceWindows,
  setMaintenanceWindows,
  userAccounts,
  setUserAccounts,
  vpnConfigs,
  setVpnConfigs
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'windows' | 'roles' | 'vpn'>('windows');
  const [showAddWindowModal, setShowAddWindowModal] = useState(false);
  const [newWindow, setNewWindow] = useState<Partial<MaintenanceWindow>>({
    id: `MW-${new Date().toISOString().slice(0, 10)}-${(maintenanceWindows.length + 1).toString().padStart(2, '0')}`,
    name: '',
    startTime: '2026-10-14T02:00:00.000Z',
    endTime: '2026-10-14T05:00:00.000Z',
    approvedAccounts: ['*'],
    approvedRoles: ['HELPDESK'],
    targetScope: ['ALL_WORKSTATIONS'],
    changeTicket: 'CHG-',
    description: '',
    status: 'ACTIVE'
  });

  const handleAddWindow = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWindow.name || !newWindow.startTime || !newWindow.endTime) return;

    const startMs = new Date(newWindow.startTime).getTime();
    const endMs = new Date(newWindow.endTime).getTime();

    const created: MaintenanceWindow = {
      id: newWindow.id || `MW-${Date.now()}`,
      name: newWindow.name,
      startTime: newWindow.startTime,
      endTime: newWindow.endTime,
      startEpochMs: startMs,
      endEpochMs: endMs,
      approvedAccounts: typeof newWindow.approvedAccounts === 'string'
        ? (newWindow.approvedAccounts as string).split(',').map(s => s.trim())
        : newWindow.approvedAccounts || ['*'],
      approvedRoles: newWindow.approvedRoles || ['HELPDESK'],
      targetScope: typeof newWindow.targetScope === 'string'
        ? (newWindow.targetScope as string).split(',').map(s => s.trim())
        : newWindow.targetScope || ['ALL_WORKSTATIONS'],
      changeTicket: newWindow.changeTicket || 'CHG-ADHOC',
      description: newWindow.description || 'Approved change maintenance',
      status: newWindow.status as any || 'ACTIVE'
    };

    setMaintenanceWindows(prev => [created, ...prev]);
    setShowAddWindowModal(false);
  };

  const toggleAccountHelpdesk = (username: string) => {
    setUserAccounts(prev => prev.map(acc => {
      if (acc.username.toLowerCase() === username.toLowerCase()) {
        const nextVal = !acc.isAuthorizedHelpdesk;
        return {
          ...acc,
          isAuthorizedHelpdesk: nextVal,
          role: nextVal ? 'HELPDESK' : 'REGULAR_USER'
        };
      }
      return acc;
    }));
  };

  const toggleAccountTraveler = (username: string) => {
    setUserAccounts(prev => prev.map(acc => {
      if (acc.username.toLowerCase() === username.toLowerCase()) {
        return {
          ...acc,
          isApprovedTraveler: !acc.isApprovedTraveler
        };
      }
      return acc;
    }));
  };

  return (
    <div>
      {/* Top Banner */}
      <div className="toolbar-card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--slate-900)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={16} />
              Operational Context &amp; False-Positive Suppression
            </div>
            <div style={{ fontSize: 11, color: 'var(--slate-500)', marginTop: 2 }}>
              Declare approved maintenance schedules, manage authorized helpdesk staff, and register company VPN gateways to differentiate authorized activity from actual compromises.
            </div>
          </div>

          <div style={{ display: 'flex', gap: 6 }}>
            <button
              className={`btn btn-sm ${activeSubTab === 'windows' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveSubTab('windows')}
            >
              <Calendar size={12} />
              Maintenance Windows ({maintenanceWindows.length})
            </button>
            <button
              className={`btn btn-sm ${activeSubTab === 'roles' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveSubTab('roles')}
            >
              <Users size={12} />
              Account Roles &amp; Helpdesk ({userAccounts.length})
            </button>
            <button
              className={`btn btn-sm ${activeSubTab === 'vpn' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveSubTab('vpn')}
            >
              <Globe size={12} />
              Corporate VPN Gateways ({vpnConfigs.length})
            </button>
          </div>
        </div>
      </div>

      {/* SubTab 1: Declared Maintenance Windows */}
      {activeSubTab === 'windows' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 12, color: 'var(--slate-600)' }}>
              When authorized helpdesk accounts connect to multiple endpoints during these active schedules, host-expansion alerts are suppressed.
            </div>
            <button className="btn btn-primary btn-sm" onClick={() => setShowAddWindowModal(true)}>
              <Plus size={12} /> Declare Maintenance Window
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(460px, 1fr))', gap: 14 }}>
            {maintenanceWindows.map(win => {
              const now = Date.now();
              const isCurrentlyActive = now >= win.startEpochMs && now <= win.endEpochMs;

              return (
                <div key={win.id} className="detail-card" style={{ margin: 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--slate-900)' }}>
                          {win.name}
                        </span>
                        <span className="mono" style={{ fontSize: 10, background: '#f1f5f9', padding: '1px 5px', borderRadius: 3 }}>
                          {win.id}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--slate-500)', marginTop: 2, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Ticket size={11} />
                        CAB Ticket: <strong>{win.changeTicket}</strong>
                      </div>
                    </div>

                    <span 
                      className="badge"
                      style={{ 
                        backgroundColor: win.status === 'ACTIVE' ? '#f0fdf4' : '#f8fafc',
                        color: win.status === 'ACTIVE' ? '#166534' : '#475569',
                        border: `1px solid ${win.status === 'ACTIVE' ? '#bbf7d0' : '#cbd5e1'}`
                      }}
                    >
                      {win.status}
                    </span>
                  </div>

                  <p style={{ fontSize: 11, color: 'var(--slate-600)', marginBottom: 10 }}>
                    {win.description}
                  </p>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 11, backgroundColor: '#f8fafc', padding: 8, borderRadius: 4, border: '1px solid #e2e8f0' }}>
                    <div>
                      <span style={{ color: '#64748b' }}>Start UTC:</span>
                      <div className="mono" style={{ fontWeight: 600 }}>{formatUtcDateTime(win.startTime)}</div>
                    </div>
                    <div>
                      <span style={{ color: '#64748b' }}>End UTC:</span>
                      <div className="mono" style={{ fontWeight: 600 }}>{formatUtcDateTime(win.endTime)}</div>
                    </div>
                    <div>
                      <span style={{ color: '#64748b' }}>Approved Roles:</span>
                      <div style={{ fontWeight: 600 }}>{win.approvedRoles.join(', ')}</div>
                    </div>
                    <div>
                      <span style={{ color: '#64748b' }}>Authorized Accounts:</span>
                      <div className="mono" style={{ fontWeight: 600 }}>{win.approvedAccounts.join(', ')}</div>
                    </div>
                    <div style={{ gridColumn: '1 / -1' }}>
                      <span style={{ color: '#64748b' }}>Approved Host Scope:</span>
                      <div className="mono" style={{ fontWeight: 600 }}>{win.targetScope.join(', ')}</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SubTab 2: Account Roles & Helpdesk Registry */}
      {activeSubTab === 'roles' && (
        <div className="table-container">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Department</th>
                <th>Authorized Helpdesk</th>
                <th>Approved Traveler</th>
                <th>Operational Context &amp; Purpose</th>
                <th style={{ textAlign: 'right' }}>Toggle Authorization</th>
              </tr>
            </thead>
            <tbody>
              {userAccounts.map(acc => {
                const isHd = acc.isAuthorizedHelpdesk;
                const isTraveler = acc.isApprovedTraveler;

                return (
                  <tr key={acc.username}>
                    <td>
                      <div className="user-cell">
                        <div className="user-avatar" style={{ backgroundColor: isHd ? '#0f172a' : '#cbd5e1', color: isHd ? '#ffffff' : '#334155' }}>
                          {acc.username.substring(0, 2).toUpperCase()}
                        </div>
                        <div>
                          <div className="user-name">{acc.username}</div>
                          <div className="mono" style={{ fontSize: 10, color: 'var(--slate-500)' }}>{acc.department}</div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className="badge" style={{ backgroundColor: isHd ? '#eff6ff' : '#f8fafc', color: isHd ? '#1e40af' : '#475569', border: '1px solid #cbd5e1' }}>
                        {acc.role}
                      </span>
                    </td>
                    <td>{acc.department}</td>
                    <td>
                      {isHd ? (
                        <span className="badge" style={{ backgroundColor: '#f0fdf4', color: '#166534', border: '1px solid #bbf7d0' }}>
                          AUTHORIZED HELPDESK
                        </span>
                      ) : (
                        <span style={{ color: 'var(--slate-400)', fontSize: 11 }}>Regular</span>
                      )}
                    </td>
                    <td>
                      {isTraveler ? (
                        <span className="badge" style={{ backgroundColor: '#f0fdf4', color: '#166534', border: '1px solid #bbf7d0' }}>
                          APPROVED TRAVELER
                        </span>
                      ) : (
                        <span style={{ color: 'var(--slate-400)', fontSize: 11 }}>Office Fixed</span>
                      )}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--slate-600)', maxWidth: 280 }}>
                      {acc.notes}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: 6 }}>
                        <button
                          className={`btn btn-sm ${isHd ? 'btn-danger' : 'btn-secondary'}`}
                          onClick={() => toggleAccountHelpdesk(acc.username)}
                          title="Toggle Helpdesk multi-host maintenance privilege"
                        >
                          {isHd ? 'Revoke Helpdesk' : 'Grant Helpdesk'}
                        </button>
                        <button
                          className={`btn btn-sm ${isTraveler ? 'btn-secondary' : 'btn-secondary'}`}
                          onClick={() => toggleAccountTraveler(acc.username)}
                          title="Toggle Business Traveler status"
                        >
                          {isTraveler ? 'Unset Travel' : 'Set Travel'}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* SubTab 3: Corporate VPN Gateways */}
      {activeSubTab === 'vpn' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(440px, 1fr))', gap: 14 }}>
          {vpnConfigs.map(vpn => (
            <div key={vpn.id} className="detail-card" style={{ margin: 0 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--slate-900)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Globe size={14} />
                    {vpn.gatewayName}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--slate-500)', marginTop: 2 }}>
                    {vpn.locationLabel}
                  </div>
                </div>

                {vpn.requiresMFA && (
                  <span className="badge badge-low">
                    MFA ENFORCED
                  </span>
                )}
              </div>

              <p style={{ fontSize: 11, color: 'var(--slate-600)', marginBottom: 10 }}>
                {vpn.description}
              </p>

              <div style={{ backgroundColor: '#f8fafc', padding: 8, borderRadius: 4, border: '1px solid #e2e8f0', fontSize: 11 }}>
                <div>
                  <span style={{ color: '#64748b' }}>Assigned VPN Subnets (CIDR):</span>
                  <div className="mono" style={{ fontWeight: 600, color: '#0f172a' }}>
                    {vpn.ipRanges.join(', ')}
                  </div>
                </div>
                <div style={{ marginTop: 4 }}>
                  <span style={{ color: '#64748b' }}>Public Gateway IPs:</span>
                  <div className="mono" style={{ fontWeight: 600, color: '#0f172a' }}>
                    {vpn.gatewayIPs.join(', ')}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Modal: Add Maintenance Window */}
      {showAddWindowModal && (
        <div className="modal-overlay" onClick={() => setShowAddWindowModal(false)}>
          <div className="modal-content" style={{ maxWidth: 540 }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">Declare Operational Maintenance Window</div>
              <button className="btn-close" onClick={() => setShowAddWindowModal(false)}>&times;</button>
            </div>
            <form onSubmit={handleAddWindow}>
              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div>
                  <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                    Window Title
                  </label>
                  <input
                    type="text"
                    required
                    className="search-input"
                    placeholder="e.g. Workstation EDR Configuration & Patching"
                    value={newWindow.name}
                    onChange={(e) => setNewWindow(p => ({ ...p, name: e.target.value }))}
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                      Start Time (UTC ISO)
                    </label>
                    <input
                      type="text"
                      required
                      className="search-input"
                      placeholder="2026-10-14T02:00:00Z"
                      value={newWindow.startTime}
                      onChange={(e) => setNewWindow(p => ({ ...p, startTime: e.target.value }))}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                      End Time (UTC ISO)
                    </label>
                    <input
                      type="text"
                      required
                      className="search-input"
                      placeholder="2026-10-14T05:00:00Z"
                      value={newWindow.endTime}
                      onChange={(e) => setNewWindow(p => ({ ...p, endTime: e.target.value }))}
                    />
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                      Approved Accounts (comma-separated or *)
                    </label>
                    <input
                      type="text"
                      className="search-input"
                      value={Array.isArray(newWindow.approvedAccounts) ? newWindow.approvedAccounts.join(', ') : newWindow.approvedAccounts}
                      onChange={(e) => setNewWindow(p => ({ ...p, approvedAccounts: e.target.value as any }))}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                      CAB Change Ticket ID
                    </label>
                    <input
                      type="text"
                      className="search-input"
                      placeholder="e.g. CHG-9842"
                      value={newWindow.changeTicket}
                      onChange={(e) => setNewWindow(p => ({ ...p, changeTicket: e.target.value }))}
                    />
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                    Approved Host Scope Pattern (e.g. ALL_WORKSTATIONS, WKSTN-*)
                  </label>
                  <input
                    type="text"
                    className="search-input"
                    value={Array.isArray(newWindow.targetScope) ? newWindow.targetScope.join(', ') : newWindow.targetScope}
                    onChange={(e) => setNewWindow(p => ({ ...p, targetScope: e.target.value as any }))}
                  />
                </div>

                <div>
                  <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                    Description &amp; Operational Rationale
                  </label>
                  <textarea
                    className="search-input"
                    style={{ height: 50, resize: 'none' }}
                    value={newWindow.description}
                    onChange={(e) => setNewWindow(p => ({ ...p, description: e.target.value }))}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowAddWindowModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Declare Window
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
