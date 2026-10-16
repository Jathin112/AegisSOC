import React, { useState } from 'react';
import { X, FileDown, FileText, CheckCircle2, ShieldAlert } from 'lucide-react';
import { UserIncident, CompanyAccessConfig } from '../types';
import { exportIncidentsToCsv, exportIncidentsToHtml } from '../utils/exportGenerator';

interface ReportExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  incidents: UserIncident[];
  currentCompany: CompanyAccessConfig;
}

export const ReportExportModal: React.FC<ReportExportModalProps> = ({
  isOpen,
  onClose,
  incidents,
  currentCompany
}) => {
  if (!isOpen) return null;

  const [analystName, setAnalystName] = useState('Senior SOC Analyst (ID: SOC-4092)');
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  const handleExportCsv = () => {
    const csvContent = exportIncidentsToCsv(incidents, currentCompany.name);
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `aegis_incidents_${currentCompany.code}_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setDownloadSuccess('CSV Export downloaded successfully.');
    setTimeout(() => setDownloadSuccess(null), 3000);
  };

  const handleExportHtml = () => {
    const htmlContent = exportIncidentsToHtml(incidents, currentCompany, analystName);
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `aegis_forensic_report_${currentCompany.code}_${new Date().toISOString().slice(0, 10)}.html`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setDownloadSuccess('Print-ready offline HTML Forensic Report downloaded.');
    setTimeout(() => setDownloadSuccess(null), 3000);
  };

  const handlePreviewHtml = () => {
    const htmlContent = exportIncidentsToHtml(incidents, currentCompany, analystName);
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: 580 }} onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <div className="brand-icon-box" style={{ width: 28, height: 28 }}>
              <FileDown size={16} />
            </div>
            <div className="modal-title">Export SOC Investigation Dossier</div>
          </div>
          <button className="btn-close" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ backgroundColor: '#f8fafc', padding: 12, borderRadius: 6, border: '1px solid #e2e8f0', fontSize: 12 }}>
            <div style={{ fontWeight: 600, color: 'var(--slate-800)', marginBottom: 4 }}>
              Active Export Scope:
            </div>
            <div style={{ color: 'var(--slate-600)', lineHeight: 1.6 }}>
              <div>Client Tenant: <strong>{currentCompany.name} ({currentCompany.code})</strong></div>
              <div>Incidents Included: <strong>{incidents.length} security incident(s)</strong></div>
              <div>Confirmed Compromises: <strong>{incidents.filter(i => i.threatClass === 'CONFIRMED_COMPROMISE').length}</strong></div>
            </div>
          </div>

          <div>
            <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 4 }}>
              Lead Investigating Analyst Name &amp; Title (Printed on Report Sign-off):
            </label>
            <input
              type="text"
              className="search-input"
              value={analystName}
              onChange={(e) => setAnalystName(e.target.value)}
              placeholder="e.g. Lead SOC Analyst John Doe"
            />
          </div>

          {downloadSuccess && (
            <div style={{ backgroundColor: '#f0fdf4', color: '#166534', border: '1px solid #bbf7d0', padding: 10, borderRadius: 4, fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
              <CheckCircle2 size={16} />
              {downloadSuccess}
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 4 }}>
            {/* HTML Report Card */}
            <div style={{ border: '1px solid #cbd5e1', borderRadius: 6, padding: 14, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', backgroundColor: '#ffffff' }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--slate-900)', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <FileText size={16} color="#0f172a" />
                  Forensic HTML Dossier
                </div>
                <p style={{ fontSize: 11, color: 'var(--slate-600)', marginTop: 6, lineHeight: 1.4 }}>
                  Standalone, print-ready offline report with executive risk matrix, evidence tables, triage checklist, and signature block.
                </p>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 14 }}>
                <button className="btn btn-primary btn-sm" onClick={handleExportHtml}>
                  <FileDown size={12} />
                  Download HTML Report
                </button>
                <button className="btn btn-secondary btn-sm" onClick={handlePreviewHtml}>
                  Open Browser Preview
                </button>
              </div>
            </div>

            {/* CSV Export Card */}
            <div style={{ border: '1px solid #cbd5e1', borderRadius: 6, padding: 14, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', backgroundColor: '#ffffff' }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--slate-900)', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <FileDown size={16} color="#0f172a" />
                  Structured CSV Export
                </div>
                <p style={{ fontSize: 11, color: 'var(--slate-600)', marginTop: 6, lineHeight: 1.4 }}>
                  Raw machine-readable tabular export containing risk scores, involved IPs/hosts, evidence metrics, and triage steps.
                </p>
              </div>

              <div style={{ marginTop: 14 }}>
                <button className="btn btn-primary btn-sm" style={{ width: '100%' }} onClick={handleExportCsv}>
                  <FileDown size={12} />
                  Download Incidents CSV
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
