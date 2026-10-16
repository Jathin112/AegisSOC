import React from 'react';
import { 
  ShieldAlert, 
  Upload, 
  FileDown, 
  Sliders, 
  Users, 
  ListFilter, 
  Building2, 
  Database,
  RefreshCw
} from 'lucide-react';
import { CompanyAccessConfig } from '../types';

interface HeaderProps {
  activeTab: 'incidents' | 'baselines' | 'rules' | 'logs' | 'companies' | 'context';
  setActiveTab: (tab: 'incidents' | 'baselines' | 'rules' | 'logs' | 'companies' | 'context') => void;
  companies: CompanyAccessConfig[];
  selectedCompanyId: string;
  onSelectCompany: (companyId: string) => void;
  onOpenUpload: () => void;
  onOpenExport: () => void;
  onOpenRulesConfig: () => void;
  onResetSampleData: () => void;
  incidentCount: number;
  confirmedCount: number;
  maintenanceCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  companies,
  selectedCompanyId,
  onSelectCompany,
  onOpenUpload,
  onOpenExport,
  onOpenRulesConfig,
  onResetSampleData,
  incidentCount,
  confirmedCount,
  maintenanceCount = 2
}) => {
  const currentCompany = companies.find(c => c.id === selectedCompanyId) || companies[0];

  return (
    <header className="soc-header">
      <div className="header-top">
        <div className="brand-section">
          <div className="brand-icon-box">
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="brand-title">
              AEGIS SOC // LOG FORENSICS
              <span className="brand-badge">AIR-GAPPED / OFFLINE</span>
              {confirmedCount > 0 && (
                <span className="badge badge-compromise" style={{ marginLeft: 6 }}>
                  {confirmedCount} COMPROMISE{confirmedCount > 1 ? 'S' : ''} DETECTED
                </span>
              )}
            </div>
            <div className="brand-subtitle">
              Context-Aware Behavioral Baselines &amp; Threat Detection Engine
            </div>
          </div>
        </div>

        <div className="header-controls">
          {/* Company / Tenant Selector */}
          <div className="company-selector-wrapper">
            <Building2 size={14} className="text-muted" />
            <span className="company-selector-label">Client Tenant:</span>
            <select
              className="company-select"
              value={selectedCompanyId}
              onChange={(e) => onSelectCompany(e.target.value)}
            >
              {companies.map(comp => (
                <option key={comp.id} value={comp.id}>
                  {comp.name} ({comp.code}) [{comp.status}]
                </option>
              ))}
            </select>
            <span 
              className={`company-status-dot ${currentCompany?.status.toLowerCase() || 'active'}`}
              title={`Tenant Status: ${currentCompany?.status} (Valid until ${currentCompany?.validUntil})`}
            />
          </div>

          <div className="header-actions">
            <button className="btn btn-secondary btn-sm" onClick={onResetSampleData} title="Reload Default Enterprise Scenario">
              <RefreshCw size={13} />
              Reset Dataset
            </button>
            <button className="btn btn-secondary btn-sm" onClick={onOpenUpload}>
              <Upload size={13} />
              Ingest Logs (CSV)
            </button>
            <button className="btn btn-primary btn-sm" onClick={onOpenExport}>
              <FileDown size={13} />
              Export Report
            </button>
          </div>
        </div>
      </div>

      <nav className="header-nav">
        <button
          className={`nav-tab ${activeTab === 'incidents' ? 'active' : ''}`}
          onClick={() => setActiveTab('incidents')}
        >
          <ListFilter size={15} />
          Incidents &amp; Triage
          {incidentCount > 0 && <span className="tab-badge">{incidentCount}</span>}
        </button>
        <button
          className={`nav-tab ${activeTab === 'context' ? 'active' : ''}`}
          onClick={() => setActiveTab('context')}
        >
          <Sliders size={15} />
          Maintenance &amp; Context
          <span className="tab-badge">{maintenanceCount} Active</span>
        </button>
        <button
          className={`nav-tab ${activeTab === 'baselines' ? 'active' : ''}`}
          onClick={() => setActiveTab('baselines')}
        >
          <Users size={15} />
          Learned User Baselines
        </button>
        <button
          className={`nav-tab ${activeTab === 'rules' ? 'active' : ''}`}
          onClick={() => setActiveTab('rules')}
        >
          <Sliders size={15} />
          Detection Rules Engine
        </button>
        <button
          className={`nav-tab ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          <Database size={15} />
          Normalized Log Explorer
        </button>
        <button
          className={`nav-tab ${activeTab === 'companies' ? 'active' : ''}`}
          onClick={() => setActiveTab('companies')}
        >
          <Building2 size={15} />
          Tenant Access Control
          <span className="tab-badge">{companies.length}</span>
        </button>
      </nav>
    </header>
  );
};
