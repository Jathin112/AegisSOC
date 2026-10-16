export type AuthAction = 'SUCCESS' | 'FAILURE';

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatClass = 'SUSPICIOUS' | 'CONFIRMED_COMPROMISE';

export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'ESCALATED' | 'REMEDIATED' | 'FALSE_POSITIVE';

export type CompanyStatus = 'ACTIVE' | 'SUSPENDED' | 'EXPIRED';

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
    repeatedFailuresThreshold?: number; // e.g. 5 failed attempts
    repeatedFailuresWindowMinutes?: number; // e.g. 10 minutes

    // Burst of Failures followed by Success
    burstFailuresMinCount?: number; // e.g. 3 failures
    burstSuccessWindowMinutes?: number; // e.g. 15 minutes

    // Password Spray
    sprayDistinctUsersMin?: number; // e.g. 4 distinct usernames from same IP
    sprayWindowMinutes?: number; // e.g. 20 minutes

    // Unusual Login Times
    unusualTimeThresholdPercentile?: number; // % of baseline activity or off-peak hours
    strictBusinessHoursOnly?: boolean; // strictly 07:00 - 19:00

    // Unfamiliar IPs/Locations
    subnetMatchOnly?: boolean; // match on /24 subnet rather than exact IP

    // Sudden Host Access Expansion
    hostExpansionNewHostsThreshold?: number; // e.g. accessing >= 2 new hosts
    hostExpansionWindowMinutes?: number; // e.g. 60 minutes
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
}
