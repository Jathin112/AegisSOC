export type AuthAction = 'SUCCESS' | 'FAILURE';

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatClass = 'SUSPICIOUS' | 'CONFIRMED_COMPROMISE';

export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'ESCALATED' | 'REMEDIATED' | 'FALSE_POSITIVE' | 'BENIGN_MAINTENANCE';

export type CompanyStatus = 'ACTIVE' | 'SUSPENDED' | 'EXPIRED';

export type AccountRole = 'REGULAR_USER' | 'HELPDESK' | 'SYSADMIN' | 'SERVICE_ACCOUNT';

export interface UserAccountConfig {
  username: string;
  role: AccountRole;
  department: string;
  isAuthorizedHelpdesk: boolean;
  isApprovedTraveler?: boolean;
  assignedWorkstations?: string[];
  notes?: string;
}

export interface MaintenanceWindow {
  id: string; // e.g. "MW-2026-10-14-01"
  name: string;
  startTime: string; // ISO 8601 string
  endTime: string; // ISO 8601 string
  startEpochMs: number;
  endEpochMs: number;
  approvedAccounts: string[]; // usernames or ["*"] for any authorized helpdesk
  approvedRoles: AccountRole[]; // e.g. ["HELPDESK", "SYSADMIN"]
  targetScope: string[]; // hostnames or patterns e.g. ["*"] or ["WKSTN-*", "FINANCE-*"]
  changeTicket: string; // e.g. "CHG-9842"
  description: string;
  status: 'SCHEDULED' | 'ACTIVE' | 'COMPLETED';
}

export interface CompanyVpnConfig {
  id: string;
  gatewayName: string; // e.g. "VPN-GW01", "CORP-VPN-PRIMARY"
  ipRanges: string[]; // e.g. ["10.250.0.0/16", "172.20.0.0/16"]
  gatewayIPs: string[]; // e.g. ["198.51.100.250", "203.0.113.10"]
  requiresMFA: boolean;
  locationLabel: string; // e.g. "Corporate Secure VPN Gateway"
  description: string;
}

export interface RawAuthLog {
  timestamp?: string;
  time?: string;
  datetime?: string;
  date?: string;
  user?: string;
  username?: string;
  account?: string;
  ip?: string;
  source_ip?: string;
  ip_address?: string;
  host?: string;
  hostname?: string;
  computer_name?: string;
  server?: string;
  action?: string;
  status?: string;
  event?: string;
  result?: string;
  reason?: string;
  failure_reason?: string;
  location?: string;
  geo?: string;
  user_agent?: string;
  [key: string]: any;
}

export interface NormalizedAuthLog {
  id: string;
  rawTimestamp: string;
  timestamp: string; // ISO 8601 string: YYYY-MM-DDTHH:mm:ss.sssZ
  dateObj: Date;
  epochMs: number;
  user: string;
  ip: string;
  host: string;
  action: AuthAction;
  failureReason: string;
  location: string;
  userAgent?: string;
  hash: string;
  isDuplicate: boolean;
  duplicateCount?: number;
  inTrainingPeriod: boolean;
  companyId?: string;

  // Context attributes
  accountRole?: AccountRole;
  isVpnLogin?: boolean;
  inMaintenanceWindow?: boolean;
  matchedMaintenanceWindowId?: string;
}

export interface UserBaseline {
  user: string;
  totalEvents: number;
  usualHours: number[]; // Hours (0-23) where activity was observed during training
  hourDistribution: Record<number, number>; // hour -> count
  usualIPs: string[];
  usualSubnets: string[]; // e.g. "192.168.1.0/24"
  usualLocations: string[];
  usualHosts: string[];
  firstSeen: string;
  lastSeen: string;
  trainingLogsCount: number;
}

export type RuleCategory =
  | 'REPEATED_FAILURES'
  | 'BURST_FAILURE_THEN_SUCCESS'
  | 'PASSWORD_SPRAY'
  | 'UNUSUAL_TIME'
  | 'UNFAMILIAR_IP'
  | 'HOST_EXPANSION';

export interface DetectionRule {
  id: string;
  name: string;
  category: RuleCategory;
  description: string;
  enabled: boolean;
  severity: SeverityLevel;
  threatClass: ThreatClass;
  baseWeight: number; // Contribution to risk score
  params: {
    // Repeated Failures
    repeatedFailuresThreshold?: number;
    repeatedFailuresWindowMinutes?: number;

    // Burst of Failures followed by Success
    burstFailuresMinCount?: number;
    burstSuccessWindowMinutes?: number;

    // Password Spray
    sprayDistinctUsersMin?: number;
    sprayWindowMinutes?: number;

    // Unusual Login Times
    unusualTimeThresholdPercentile?: number;
    strictBusinessHoursOnly?: boolean;

    // Unfamiliar IPs/Locations
    subnetMatchOnly?: boolean;

    // Sudden Host Access Expansion
    hostExpansionNewHostsThreshold?: number;
    hostExpansionWindowMinutes?: number;

    // Context & False Positive Reduction Toggles
    considerMaintenanceWindows?: boolean;
    suppressAuthorizedHelpdeskInWindow?: boolean;
    trustCorporateVpnForTravelers?: boolean;
  };
}

export interface DetectionAlert {
  id: string;
  ruleId: string;
  ruleCategory: RuleCategory;
  ruleName: string;
  user: string;
  timestamp: string;
  severity: SeverityLevel;
  threatClass: ThreatClass;
  score: number;
  summary: string;
  evidence: NormalizedAuthLog[];
  details: Record<string, any>;

  // Context & Decision Transparency
  contextFlags?: string[];
  decisionExplanation?: string;
  isContextSuppressed?: boolean;
  suppressionReason?: string;

  // Confidence & Evidence Strength (Mission 3)
  confidenceScore?: number; // 0 - 100%
  confidenceLabel?: 'VERY_HIGH' | 'HIGH' | 'MODERATE' | 'LOW';
  evidenceStrength?: 'VERY_STRONG' | 'STRONG' | 'MODERATE' | 'WEAK';
}

export interface RiskScoreContribution {
  ruleId: string;
  ruleName: string;
  category: RuleCategory;
  pointsAdded: number; // Positive contribution or negative mitigation
  percentageOfTotal: number;
  reason: string;
  evidenceCount: number;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'USER' | 'IP' | 'HOST';
  isBaseline?: boolean;
  isNovel?: boolean;
  isCritical?: boolean;
  isVpn?: boolean;
  failCount: number;
  successCount: number;
  details?: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  action: 'SUCCESS' | 'FAILURE' | 'MIXED';
  count: number;
  isNovelPath?: boolean;
}

export interface UserHostGraph {
  user: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  totalHostsAccessed: number;
  novelHostsCount: number;
  baselineHostsCount: number;
}

export interface IncidentTimelineEvent {
  id: string;
  timestamp: string; // ISO 8601 UTC
  epochMs: number;
  type: 'AUTH_SUCCESS' | 'AUTH_FAILURE' | 'DETECTION_ALERT';
  title: string;
  description: string;
  ip?: string;
  host?: string;
  severity?: SeverityLevel;
  alertId?: string;
  ruleCategory?: RuleCategory;
  confidence?: string;
  isSuspicious: boolean;
  failureReason?: string;
  location?: string;
}

export interface IncidentNote {
  id: string;
  author: string;
  timestamp: string;
  text: string;
}

export interface UserIncident {
  id: string;
  companyId: string;
  user: string;
  riskScore: number; // 0 - 100
  severity: SeverityLevel;
  threatClass: ThreatClass;
  status: IncidentStatus;
  alerts: DetectionAlert[];
  triggeredRuleCategories: RuleCategory[];
  evidenceRows: NormalizedAuthLog[];
  evidenceCount: number;
  firstSeen: string;
  lastSeen: string;
  involvedHosts: string[];
  involvedIPs: string[];
  recommendedTriageSteps: string[];
  notes: IncidentNote[];
  assignedTo?: string;
  updatedAt: string;

  // Context & Decision Transparency
  accountRole?: AccountRole;
  isHelpdesk?: boolean;
  isTravelingEmployee?: boolean;
  contextFlags?: string[];
  decisionExplanation?: string;
  isContextSuppressed?: boolean;
  maintenanceWindowId?: string;

  // Mission 3: Visualizations & Traceability
  riskBreakdown?: RiskScoreContribution[];
  hostGraph?: UserHostGraph;
  timelineEvents?: IncidentTimelineEvent[];
}

export interface TrainingPeriodConfig {
  mode: 'PERCENTAGE' | 'DATE_RANGE' | 'FIRST_N_DAYS';
  percentage?: number; // e.g. 40%
  startDate?: string;
  endDate?: string;
  firstNDays?: number;
}

export interface CompanyAccessConfig {
  id: string;
  name: string;
  code: string;
  status: CompanyStatus;
  validUntil: string; // ISO date string e.g. "2026-12-31"
  contactEmail: string;
  maxSeats: number;
  socAnalystAccess: boolean;
  allowedSubnets: string[];
  description: string;
  updatedAt: string;
}

export interface FilterState {
  searchQuery: string;
  severity: 'ALL' | SeverityLevel;
  threatClass: 'ALL' | ThreatClass;
  ruleCategory: 'ALL' | RuleCategory;
  status: 'ALL' | IncidentStatus;
  user: string;
  host: string;
  companyId: string;
  contextFilter?: 'ALL' | 'ACTIONABLE_ONLY' | 'SUPPRESSED_MAINTENANCE' | 'VPN_TRAVEL';
}
