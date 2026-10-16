import React, { useState, useEffect, useMemo } from 'react';
import { 
  NormalizedAuthLog, 
  UserBaseline, 
  DetectionRule, 
  DetectionAlert, 
  UserIncident, 
  TrainingPeriodConfig, 
  CompanyAccessConfig, 
  FilterState, 
  IncidentStatus 
} from './types';
import { DEFAULT_RULES } from './config/defaultRules';
import { DEFAULT_COMPANIES } from './config/defaultCompanies';
import { SAMPLE_CSV_LOGS } from './data/sampleLogs';
import { parseAuthLogsCsv } from './utils/csvParser';
import { deduplicateLogs } from './utils/logDeduplicator';
import { learnBaselines } from './utils/baselineLearner';
import { runDetectionRules } from './utils/rulesEngine';
import { aggregateIncidents } from './utils/incidentAggregator';

// Components
import { Header } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { FilterBar } from './components/FilterBar';
import { IncidentTable } from './components/IncidentTable';
import { IncidentDetailModal } from './components/IncidentDetailModal';
import { BaselineViewer } from './components/BaselineViewer';
import { RulesConfigModal } from './components/RulesConfigModal';
import { LogsExplorer } from './components/LogsExplorer';
import { CompanyAccessManager } from './components/CompanyAccessManager';
import { ReportExportModal } from './components/ReportExportModal';
import { LogUploadModal } from './components/LogUploadModal';
import { ShieldAlert, AlertTriangle, Lock, Unlock } from 'lucide-react';

export function App() {
  // Enterprise Tenant State
  const [companies, setCompanies] = useState<CompanyAccessConfig[]>(DEFAULT_COMPANIES);
  const [selectedCompanyId, setSelectedCompanyId] = useState<string>('COMP-001');

  // Logs & Processing State
  const [allLogs, setAllLogs] = useState<NormalizedAuthLog[]>([]);
  const [uniqueLogs, setUniqueLogs] = useState<NormalizedAuthLog[]>([]);
  const [duplicateCount, setDuplicateCount] = useState<number>(0);

  // Baseline Learning State
  const [trainingConfig, setTrainingConfig] = useState<TrainingPeriodConfig>({
    mode: 'PERCENTAGE',
    percentage: 50
  });
  const [baselines, setBaselines] = useState<Map<string, UserBaseline>>(new Map());
  const [trainingCutoff, setTrainingCutoff] = useState<string>('');
  const [trainingLogCount, setTrainingLogCount] = useState<number>(0);
  const [evaluationLogCount, setEvaluationLogCount] = useState<number>(0);

  // Rules & Incident State
  const [rules, setRules] = useState<DetectionRule[]>(DEFAULT_RULES);
  const [alerts, setAlerts] = useState<DetectionAlert[]>([]);
  const [incidents, setIncidents] = useState<UserIncident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<UserIncident | null>(null);

  // UI Navigation & Filters State
  const [activeTab, setActiveTab] = useState<'incidents' | 'baselines' | 'rules' | 'logs' | 'companies'>('incidents');
  const [filters, setFilters] = useState<FilterState>({
    searchQuery: '',
    severity: 'ALL',
    threatClass: 'ALL',
    ruleCategory: 'ALL',
    status: 'ALL',
    user: '',
    host: '',
    companyId: 'COMP-001'
  });

  // Modals
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [isExportOpen, setIsExportOpen] = useState(false);

  // Current Company object
  const currentCompany = useMemo(() => {
    return companies.find(c => c.id === selectedCompanyId) || companies[0];
  }, [companies, selectedCompanyId]);

  const isCompanyLocked = useMemo(() => {
    if (!currentCompany) return false;
    const isPast = new Date(currentCompany.validUntil).getTime() < new Date().getTime();
    return currentCompany.status === 'SUSPENDED' || currentCompany.status === 'EXPIRED' || isPast;
  }, [currentCompany]);

  // Initial Data Ingestion
  useEffect(() => {
    processCsvLogs(SAMPLE_CSV_LOGS, 50, selectedCompanyId);
  }, []);

  // Process raw CSV string
  const processCsvLogs = (csvContent: string, trainingPct: number = 50, companyId: string = selectedCompanyId) => {
    const parseRes = parseAuthLogsCsv(csvContent, companyId);
    setAllLogs(parseRes.logs);

    // Deduplication
    const dedupRes = deduplicateLogs(parseRes.logs);
    setUniqueLogs(dedupRes.uniqueLogs);
    setDuplicateCount(dedupRes.duplicateCount);

    // Learn Baselines
    const currentTrainingConfig: TrainingPeriodConfig = {
      mode: 'PERCENTAGE',
      percentage: trainingPct
    };
    setTrainingConfig(currentTrainingConfig);

    const baselineRes = learnBaselines(dedupRes.uniqueLogs, currentTrainingConfig);
    setBaselines(baselineRes.baselines);
    setTrainingCutoff(baselineRes.trainingCutoffTimestamp);
    setTrainingLogCount(baselineRes.trainingLogCount);
    setEvaluationLogCount(baselineRes.evaluationLogCount);

    // Run Detection Rules
    const generatedAlerts = runDetectionRules(dedupRes.uniqueLogs, baselineRes.baselines, rules);
    setAlerts(generatedAlerts);

    // Aggregate Incidents
    const generatedIncidents = aggregateIncidents(generatedAlerts, companyId);
    setIncidents(generatedIncidents);
  };

  // Re-run rules whenever rules or trainingConfig change
  useEffect(() => {
    if (uniqueLogs.length === 0) return;

    // Re-learn baselines with current config
    const baselineRes = learnBaselines(uniqueLogs, trainingConfig);
    setBaselines(baselineRes.baselines);
    setTrainingCutoff(baselineRes.trainingCutoffTimestamp);
    setTrainingLogCount(baselineRes.trainingLogCount);
    setEvaluationLogCount(baselineRes.evaluationLogCount);

    // Re-run rules
    const generatedAlerts = runDetectionRules(uniqueLogs, baselineRes.baselines, rules);
    setAlerts(generatedAlerts);

    // Re-aggregate incidents (preserve status & notes of existing incidents where applicable)
    setIncidents(prevIncidents => {
      const fresh = aggregateIncidents(generatedAlerts, selectedCompanyId);
      return fresh.map(newInc => {
        const existing = prevIncidents.find(old => old.user.toLowerCase() === newInc.user.toLowerCase());
        if (existing) {
          return {
            ...newInc,
            status: existing.status,
            notes: [...existing.notes]
          };
        }
        return newInc;
      });
    });
  }, [rules, trainingConfig]);

  // Update incident status
  const handleUpdateStatus = (incidentId: string, status: IncidentStatus) => {
    setIncidents(prev => prev.map(inc => {
      if (inc.id === incidentId) {
        const updated = {
          ...inc,
          status,
          updatedAt: new Date().toISOString()
        };
        if (selectedIncident && selectedIncident.id === incidentId) {
          setSelectedIncident(updated);
        }
        return updated;
      }
      return inc;
    }));
  };

  // Add note to incident
  const handleAddNote = (incidentId: string, text: string) => {
    const note = {
      id: `NOTE-${Date.now()}`,
      author: 'Lead SOC Analyst',
      timestamp: new Date().toISOString(),
      text
    };

    setIncidents(prev => prev.map(inc => {
      if (inc.id === incidentId) {
        const updated = {
          ...inc,
          notes: [note, ...inc.notes],
          updatedAt: new Date().toISOString()
        };
        if (selectedIncident && selectedIncident.id === incidentId) {
          setSelectedIncident(updated);
        }
        return updated;
      }
      return inc;
    }));
  };

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    return incidents.filter(inc => {
      if (filters.severity !== 'ALL' && inc.severity !== filters.severity) return false;
      if (filters.threatClass !== 'ALL' && inc.threatClass !== filters.threatClass) return false;
      if (filters.status !== 'ALL' && inc.status !== filters.status) return false;
      if (filters.ruleCategory !== 'ALL' && !inc.triggeredRuleCategories.includes(filters.ruleCategory as any)) return false;
      if (filters.user && inc.user.toLowerCase() !== filters.user.toLowerCase()) return false;
      if (filters.host && !inc.involvedHosts.some(h => h.toLowerCase() === filters.host.toLowerCase())) return false;

      if (!filters.searchQuery) return true;
      const q = filters.searchQuery.toLowerCase();
      return (
        inc.user.toLowerCase().includes(q) ||
        inc.id.toLowerCase().includes(q) ||
        inc.involvedHosts.some(h => h.toLowerCase().includes(q)) ||
        inc.involvedIPs.some(ip => ip.includes(q)) ||
        inc.triggeredRuleCategories.some(cat => cat.toLowerCase().includes(q))
      );
    });
  }, [incidents, filters]);

  // Unique list of users & hosts for dropdowns
  const uniqueUsers = useMemo(() => {
    return Array.from(new Set(allLogs.map(l => l.user).filter(Boolean))).sort();
  }, [allLogs]);

  const uniqueHosts = useMemo(() => {
    return Array.from(new Set(allLogs.map(l => l.host).filter(Boolean))).sort();
  }, [allLogs]);

  const handleResetFilters = () => {
    setFilters({
      searchQuery: '',
      severity: 'ALL',
      threatClass: 'ALL',
      ruleCategory: 'ALL',
      status: 'ALL',
      user: '',
      host: '',
      companyId: selectedCompanyId
    });
  };

  const confirmedCount = useMemo(() => {
    return incidents.filter(i => i.threatClass === 'CONFIRMED_COMPROMISE').length;
  }, [incidents]);

  return (
    <div className="app-container">
      {/* Top Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        companies={companies}
        selectedCompanyId={selectedCompanyId}
        onSelectCompany={setSelectedCompanyId}
        onOpenUpload={() => setIsUploadOpen(true)}
        onOpenExport={() => setIsExportOpen(true)}
        onOpenRulesConfig={() => setActiveTab('rules')}
        onResetSampleData={() => processCsvLogs(SAMPLE_CSV_LOGS, 50, selectedCompanyId)}
        incidentCount={incidents.length}
        confirmedCount={confirmedCount}
      />

      {/* Main Body Content */}
      <main className="main-content">
        {/* Enterprise Lockout Banner if Company access is suspended or expired */}
        {isCompanyLocked && (
          <div className="lockout-banner">
            <div className="lockout-info">
              <Lock size={20} />
              <div>
                <div className="lockout-title">
                  TENANT ACCESS RESTRICTED: {currentCompany.name} ({currentCompany.status})
                </div>
                <div className="lockout-desc">
                  This client organization’s SOC access has been revoked or expired (Valid Until: {currentCompany.validUntil}). Admin intervention is required to reactivate monitoring.
                </div>
              </div>
            </div>
            <button
              className="btn btn-sm"
              style={{ backgroundColor: '#be123c', color: '#ffffff', border: 'none' }}
              onClick={() => setActiveTab('companies')}
            >
              Manage Tenant Authorization
            </button>
          </div>
        )}

        {/* Tab 1: Incidents & Triage */}
        {activeTab === 'incidents' && (
          <>
            <MetricCards
              totalLogs={allLogs.length}
              duplicateCount={duplicateCount}
              uniqueLogsCount={uniqueLogs.length}
              incidents={incidents}
            />

            <FilterBar
              filters={filters}
              setFilters={setFilters}
              trainingConfig={trainingConfig}
              setTrainingConfig={setTrainingConfig}
              onResetFilters={handleResetFilters}
              uniqueUsers={uniqueUsers}
              uniqueHosts={uniqueHosts}
            />

            <IncidentTable
              incidents={filteredIncidents}
              onSelectIncident={(inc) => setSelectedIncident(inc)}
              onUpdateStatus={handleUpdateStatus}
            />
          </>
        )}

        {/* Tab 2: User Baselines */}
        {activeTab === 'baselines' && (
          <BaselineViewer
            baselines={baselines}
            trainingCutoff={trainingCutoff}
            trainingLogCount={trainingLogCount}
            totalEvaluationCount={evaluationLogCount}
            trainingConfig={trainingConfig}
          />
        )}

        {/* Tab 3: Detection Rules */}
        {activeTab === 'rules' && (
          <RulesConfigModal
            rules={rules}
            setRules={setRules}
            onResetDefaults={() => setRules(DEFAULT_RULES)}
          />
        )}

        {/* Tab 4: Normalized Logs Explorer */}
        {activeTab === 'logs' && (
          <LogsExplorer logs={allLogs} />
        )}

        {/* Tab 5: Enterprise Multi-Tenant Access */}
        {activeTab === 'companies' && (
          <CompanyAccessManager
            companies={companies}
            setCompanies={setCompanies}
            selectedCompanyId={selectedCompanyId}
            onSelectCompany={setSelectedCompanyId}
          />
        )}
      </main>

      {/* Incident Detail / Investigation Modal */}
      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          baseline={baselines.get(selectedIncident.user.toLowerCase().trim())}
          onClose={() => setSelectedIncident(null)}
          onUpdateStatus={handleUpdateStatus}
          onAddNote={handleAddNote}
        />
      )}

      {/* Log Ingest / Upload Modal */}
      <LogUploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onIngestCsv={(content, trainingPct) => processCsvLogs(content, trainingPct, selectedCompanyId)}
      />

      {/* Report Export Modal */}
      <ReportExportModal
        isOpen={isExportOpen}
        onClose={() => setIsExportOpen(false)}
        incidents={filteredIncidents}
        currentCompany={currentCompany}
      />
    </div>
  );
}

export default App;
