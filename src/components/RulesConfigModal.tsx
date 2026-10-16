import React, { useRef } from 'react';
import { 
  Sliders, 
  Download, 
  Upload, 
  RotateCcw, 
  CheckCircle2, 
  AlertTriangle,
  Info
} from 'lucide-react';
import { DetectionRule, SeverityLevel, ThreatClass } from '../types';

interface RulesConfigModalProps {
  rules: DetectionRule[];
  setRules: React.Dispatch<React.SetStateAction<DetectionRule[]>>;
  onResetDefaults: () => void;
}

export const RulesConfigModal: React.FC<RulesConfigModalProps> = ({
  rules,
  setRules,
  onResetDefaults
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const toggleRuleEnabled = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const updateRuleParam = (id: string, paramKey: string, value: any) => {
    setRules(prev => prev.map(r => {
      if (r.id === id) {
        return {
          ...r,
          params: {
            ...r.params,
            [paramKey]: value
          }
        };
      }
      return r;
    }));
  };

  const updateRuleMeta = (id: string, field: 'severity' | 'threatClass' | 'baseWeight', value: any) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, [field]: value } : r));
  };

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(rules, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `aegis_detection_rules_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleImportJson = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const imported = JSON.parse(event.target?.result as string);
        if (Array.isArray(imported)) {
          setRules(imported);
          alert('Detection rules successfully imported.');
        } else {
          alert('Invalid rules file: Root element must be an array.');
        }
      } catch (err: any) {
        alert('Failed to parse JSON file: ' + err.message);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  return (
    <div>
      {/* Top action banner */}
      <div className="toolbar-card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--slate-900)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Sliders size={16} />
              Transparent Anomaly Detection Rules Engine
            </div>
            <div style={{ fontSize: 11, color: 'var(--slate-500)', marginTop: 2 }}>
              Fully configurable offline heuristics &amp; behavioral thresholds. All weights map directly into incident risk score (0-100).
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input
              type="file"
              ref={fileInputRef}
              style={{ display: 'none' }}
              accept=".json"
              onChange={handleImportJson}
            />
            <button className="btn btn-secondary btn-sm" onClick={() => fileInputRef.current?.click()}>
              <Upload size={12} />
              Import Rules JSON
            </button>
            <button className="btn btn-secondary btn-sm" onClick={handleExportJson}>
              <Download size={12} />
              Export Rules JSON
            </button>
            <button className="btn btn-secondary btn-sm" onClick={onResetDefaults}>
              <RotateCcw size={12} />
              Reset Defaults
            </button>
          </div>
        </div>
      </div>

      {/* Rules Cards List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {rules.map((rule) => {
          return (
            <div
              key={rule.id}
              className="detail-card"
              style={{
                margin: 0,
                opacity: rule.enabled ? 1 : 0.6,
                borderLeft: rule.threatClass === 'CONFIRMED_COMPROMISE' ? '4px solid #991b1b' : '4px solid #334155'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <input
                      type="checkbox"
                      id={`enable-${rule.id}`}
                      checked={rule.enabled}
                      onChange={() => toggleRuleEnabled(rule.id)}
                      style={{ cursor: 'pointer', width: 16, height: 16 }}
                    />
                    <label htmlFor={`enable-${rule.id}`} style={{ fontSize: 14, fontWeight: 700, color: 'var(--slate-900)', cursor: 'pointer' }}>
                      {rule.name}
                    </label>
                    <span className="mono" style={{ fontSize: 10, color: 'var(--slate-500)', background: '#f1f5f9', padding: '1px 5px', borderRadius: 3 }}>
                      {rule.id}
                    </span>
                  </div>
                  <p style={{ fontSize: 12, color: 'var(--slate-600)', marginTop: 4, maxWidth: 850 }}>
                    {rule.description}
                  </p>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {rule.threatClass === 'CONFIRMED_COMPROMISE' ? (
                    <span className="badge badge-compromise">CONFIRMED COMPROMISE</span>
                  ) : (
                    <span className="badge badge-suspicious">SUSPICIOUS INDICATION</span>
                  )}
                </div>
              </div>

              {/* Thresholds and Tuners */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, backgroundColor: '#f8fafc', padding: 12, borderRadius: 4, border: '1px solid #e2e8f0', marginTop: 10, fontSize: 11 }}>
                {/* Param 1 depending on rule */}
                {rule.category === 'REPEATED_FAILURES' && (
                  <>
                    <div>
                      <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                        Failure Count Threshold
                      </label>
                      <input
                        type="number"
                        min={2}
                        max={50}
                        className="search-input"
                        style={{ padding: '4px 8px', fontSize: 11 }}
                        value={rule.params.repeatedFailuresThreshold || 4}
                        onChange={(e) => updateRuleParam(rule.id, 'repeatedFailuresThreshold', Number(e.target.value))}
                      />
                    </div>
                    <div>
                      <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                        Sliding Window (Minutes)
                      </label>
                      <input
                        type="number"
                        min={1}
                        max={180}
                        className="search-input"
                        style={{ padding: '4px 8px', fontSize: 11 }}
                        value={rule.params.repeatedFailuresWindowMinutes || 10}
                        onChange={(e) => updateRuleParam(rule.id, 'repeatedFailuresWindowMinutes', Number(e.target.value))}
                      />
                    </div>
                  </>
                )}

                {rule.category === 'BURST_FAILURE_THEN_SUCCESS' && (
                  <>
                    <div>
                      <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                        Preceding Failures Min Count
                      </label>
                      <input
                        type="number"
                        min={1}
                        max={30}
                        className="search-input"
                        style={{ padding: '4px 8px', fontSize: 11 }}
                        value={rule.params.burstFailuresMinCount || 3}
                        onChange={(e) => updateRuleParam(rule.id, 'burstFailuresMinCount', Number(e.target.value))}
                      />
                    </div>
                    <div>
                      <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                        Success Window (Minutes)
                      </label>
                      <input
                        type="number"
                        min={1}
                        max={120}
                        className="search-input"
                        style={{ padding: '4px 8px', fontSize: 11 }}
                        value={rule.params.burstSuccessWindowMinutes || 15}
                        onChange={(e) => updateRuleParam(rule.id, 'burstSuccessWindowMinutes', Number(e.target.value))}
                      />
                    </div>
                  </>
                )}

                {rule.category === 'PASSWORD_SPRAY' && (
                  <>
                    <div>
                      <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                        Distinct Users Min Count
                      </label>
                      <input
                        type="number"
                        min={2}
                        max={50}
                        className="search-input"
                        style={{ padding: '4px 8px', fontSize: 11 }}
                        value={rule.params.sprayDistinctUsersMin || 3}
                        onChange={(e) => updateRuleParam(rule.id, 'sprayDistinctUsersMin', Number(e.target.value))}
                      />
                    </div>
                    <div>
                      <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                        Spray Window (Minutes)
                      </label>
                      <input
                        type="number"
                        min={1}
                        max={240}
                        className="search-input"
                        style={{ padding: '4px 8px', fontSize: 11 }}
                        value={rule.params.sprayWindowMinutes || 20}
                        onChange={(e) => updateRuleParam(rule.id, 'sprayWindowMinutes', Number(e.target.value))}
                      />
                    </div>
                  </>
                )}

                {rule.category === 'HOST_EXPANSION' && (
                  <>
                    <div>
                      <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                        New Unseen Hosts Threshold
                      </label>
                      <input
                        type="number"
                        min={1}
                        max={10}
                        className="search-input"
                        style={{ padding: '4px 8px', fontSize: 11 }}
                        value={rule.params.hostExpansionNewHostsThreshold || 1}
                        onChange={(e) => updateRuleParam(rule.id, 'hostExpansionNewHostsThreshold', Number(e.target.value))}
                      />
                    </div>
                    <div>
                      <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                        Expansion Window (Minutes)
                      </label>
                      <input
                        type="number"
                        min={5}
                        max={360}
                        className="search-input"
                        style={{ padding: '4px 8px', fontSize: 11 }}
                        value={rule.params.hostExpansionWindowMinutes || 60}
                        onChange={(e) => updateRuleParam(rule.id, 'hostExpansionWindowMinutes', Number(e.target.value))}
                      />
                    </div>
                  </>
                )}

                {rule.category === 'UNFAMILIAR_IP' && (
                  <div>
                    <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                      IP Matching Resolution
                    </label>
                    <select
                      className="filter-select"
                      style={{ width: '100%', fontSize: 11, padding: '4px 8px' }}
                      value={rule.params.subnetMatchOnly ? 'SUBNET' : 'EXACT_IP'}
                      onChange={(e) => updateRuleParam(rule.id, 'subnetMatchOnly', e.target.value === 'SUBNET')}
                    >
                      <option value="EXACT_IP">Strict Exact IP Address</option>
                      <option value="SUBNET">Permissive /24 Subnet Match</option>
                    </select>
                  </div>
                )}

                {/* Common Weights & Severity Selectors */}
                <div>
                  <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                    Rule Severity
                  </label>
                  <select
                    className="filter-select"
                    style={{ width: '100%', fontSize: 11, padding: '4px 8px' }}
                    value={rule.severity}
                    onChange={(e) => updateRuleMeta(rule.id, 'severity', e.target.value as SeverityLevel)}
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                    Threat Classification
                  </label>
                  <select
                    className="filter-select"
                    style={{ width: '100%', fontSize: 11, padding: '4px 8px' }}
                    value={rule.threatClass}
                    onChange={(e) => updateRuleMeta(rule.id, 'threatClass', e.target.value as ThreatClass)}
                  >
                    <option value="CONFIRMED_COMPROMISE">CONFIRMED COMPROMISE</option>
                    <option value="SUSPICIOUS">SUSPICIOUS INDICATION</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontWeight: 600, color: '#475569', display: 'block', marginBottom: 2 }}>
                    Base Risk Weight (0-100)
                  </label>
                  <input
                    type="number"
                    min={5}
                    max={100}
                    className="search-input"
                    style={{ padding: '4px 8px', fontSize: 11 }}
                    value={rule.baseWeight}
                    onChange={(e) => updateRuleMeta(rule.id, 'baseWeight', Number(e.target.value))}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
