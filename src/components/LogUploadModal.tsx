import React, { useState, useRef } from 'react';
import { X, Upload, FileText, CheckCircle2, AlertCircle, Database, Play } from 'lucide-react';
import { SAMPLE_CSV_LOGS, CLEAN_BENCHMARK_CSV } from '../data/sampleLogs';
import { TrainingPeriodConfig } from '../types';

interface LogUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onIngestCsv: (csvContent: string, trainingPct: number) => void;
}

export const LogUploadModal: React.FC<LogUploadModalProps> = ({
  isOpen,
  onClose,
  onIngestCsv
}) => {
  if (!isOpen) return null;

  const [activeTab, setActiveTab] = useState<'upload' | 'paste' | 'preset'>('preset');
  const [pastedCsv, setPastedCsv] = useState('');
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [fileContent, setFileContent] = useState<string>('');
  const [trainingPercentage, setTrainingPercentage] = useState<number>(50);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setSelectedFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      setFileContent(event.target?.result as string);
    };
    reader.readAsText(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setSelectedFileName(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setFileContent(event.target?.result as string);
      };
      reader.readAsText(file);
    }
  };

  const handleProcess = () => {
    let contentToIngest = '';
    if (activeTab === 'preset') {
      contentToIngest = SAMPLE_CSV_LOGS;
    } else if (activeTab === 'upload') {
      contentToIngest = fileContent;
    } else if (activeTab === 'paste') {
      contentToIngest = pastedCsv;
    }

    if (!contentToIngest.trim()) {
      alert('Please provide CSV authentication log content to analyze.');
      return;
    }

    onIngestCsv(contentToIngest, trainingPercentage);
    onClose();
  };

  const loadPreset = (preset: 'attack' | 'clean') => {
    const content = preset === 'attack' ? SAMPLE_CSV_LOGS : CLEAN_BENCHMARK_CSV;
    onIngestCsv(content, trainingPercentage);
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: 650 }} onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <div className="brand-icon-box" style={{ width: 28, height: 28 }}>
              <Upload size={16} />
            </div>
            <div className="modal-title">Ingest Authentication Logs (CSV)</div>
          </div>
          <button className="btn-close" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Sub-Tabs */}
          <div style={{ display: 'flex', gap: 6, borderBottom: '1px solid #e2e8f0', paddingBottom: 8 }}>
            <button
              className={`btn btn-sm ${activeTab === 'preset' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('preset')}
            >
              Enterprise Simulation Presets
            </button>
            <button
              className={`btn btn-sm ${activeTab === 'upload' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('upload')}
            >
              Upload CSV File
            </button>
            <button
              className={`btn btn-sm ${activeTab === 'paste' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('paste')}
            >
              Paste CSV Text
            </button>
          </div>

          {/* Preset Tab */}
          {activeTab === 'preset' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <p style={{ fontSize: 12, color: 'var(--slate-600)' }}>
                Select an enterprise scenario dataset containing labeled baseline training windows and multi-stage simulated security anomalies:
              </p>

              <div
                style={{
                  border: '1px solid #cbd5e1',
                  borderRadius: 6,
                  padding: 12,
                  cursor: 'pointer',
                  backgroundColor: '#f8fafc',
                  transition: 'border-color 0.15s ease'
                }}
                onClick={() => loadPreset('attack')}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--slate-900)' }}>
                    Enterprise Multi-Attack Scenario (Recommended)
                  </div>
                  <span className="badge badge-compromise">4 ATTACK CAMPAIGNS</span>
                </div>
                <p style={{ fontSize: 11, color: 'var(--slate-600)', marginTop: 4 }}>
                  Features 4-day corporate baseline training followed by Brute-Force cracking on Sarah (Bucharest IP), Horizontal Password Spraying from Tor IP, Lateral movement by Dave across DC01 and Vault, and Off-hours anomaly on Charlie from Sofia. Includes duplicate logs.
                </p>
                <div style={{ marginTop: 8 }}>
                  <button className="btn btn-primary btn-sm" onClick={() => loadPreset('attack')}>
                    <Play size={11} /> Load &amp; Analyze Dataset
                  </button>
                </div>
              </div>

              <div
                style={{
                  border: '1px solid #cbd5e1',
                  borderRadius: 6,
                  padding: 12,
                  cursor: 'pointer',
                  backgroundColor: '#ffffff'
                }}
                onClick={() => loadPreset('clean')}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--slate-900)' }}>
                    Clean Enterprise Baseline Benchmark
                  </div>
                  <span className="badge badge-low">CLEAN / BENCHMARK</span>
                </div>
                <p style={{ fontSize: 11, color: 'var(--slate-600)', marginTop: 4 }}>
                  Legitimate corporate logins across habitual business hours without security violations. Ideal for testing baseline model stabilization and verifying zero false positives.
                </p>
                <div style={{ marginTop: 8 }}>
                  <button className="btn btn-secondary btn-sm" onClick={() => loadPreset('clean')}>
                    <Play size={11} /> Load Clean Baseline
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Upload File Tab */}
          {activeTab === 'upload' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <input
                type="file"
                ref={fileInputRef}
                style={{ display: 'none' }}
                accept=".csv,.txt,.log"
                onChange={handleFileChange}
              />
              <div
                onDragOver={handleDragOver}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                style={{
                  border: '2px dashed #cbd5e1',
                  borderRadius: 8,
                  padding: 30,
                  textAlign: 'center',
                  cursor: 'pointer',
                  backgroundColor: '#f8fafc'
                }}
              >
                <Database size={32} style={{ color: '#64748b', margin: '0 auto 8px auto' }} />
                <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--slate-800)' }}>
                  {selectedFileName ? `Selected: ${selectedFileName}` : 'Click to browse or drag & drop CSV file here'}
                </div>
                <div style={{ fontSize: 11, color: 'var(--slate-500)', marginTop: 4 }}>
                  Accepts standard authentication logs (RFC4180 CSV with headers: timestamp, user, ip, host, action, reason)
                </div>
              </div>
            </div>
          )}

          {/* Paste Tab */}
          {activeTab === 'paste' && (
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: '#475569', display: 'block', marginBottom: 4 }}>
                Raw CSV Log Data (Header row required):
              </label>
              <textarea
                className="search-input mono"
                style={{ height: 160, resize: 'vertical', fontSize: 11 }}
                placeholder={`timestamp,user,ip,host,action,reason,location\n2026-10-10 08:30:00,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal LAN`}
                value={pastedCsv}
                onChange={(e) => setPastedCsv(e.target.value)}
              />
            </div>
          )}

          {/* Training Baseline Window Configuration */}
          <div style={{ backgroundColor: '#f1f5f9', padding: 12, borderRadius: 6, border: '1px solid #cbd5e1' }}>
            <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--slate-800)', display: 'block', marginBottom: 4 }}>
              Baseline Training Period Window:
            </label>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <input
                type="range"
                min={10}
                max={90}
                step={5}
                value={trainingPercentage}
                onChange={(e) => setTrainingPercentage(Number(e.target.value))}
                style={{ flex: 1 }}
              />
              <span className="mono" style={{ fontWeight: 700, fontSize: 13, minWidth: 100 }}>
                First {trainingPercentage}% of logs
              </span>
            </div>
            <div style={{ fontSize: 10, color: 'var(--slate-500)', marginTop: 4 }}>
              The engine will learn habitual login hours, IP subnets, and host profiles from the first {trainingPercentage}% of chronological records, and evaluate the subsequent {100 - trainingPercentage}% for behavioral anomalies.
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          {activeTab !== 'preset' && (
            <button className="btn btn-primary" onClick={handleProcess}>
              Ingest &amp; Analyze Logs
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
