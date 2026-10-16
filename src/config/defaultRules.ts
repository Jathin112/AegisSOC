import { DetectionRule } from '../types';

export const DEFAULT_RULES: DetectionRule[] = [
  {
    id: 'RULE-001',
    name: 'Repeated Authentication Failures',
    category: 'REPEATED_FAILURES',
    description: 'Detects a cluster of failed login attempts targeting a single account within a sliding time window, indicative of brute-force or dictionary attacks.',
    enabled: true,
    severity: 'MEDIUM',
    threatClass: 'SUSPICIOUS',
    baseWeight: 25,
    params: {
      repeatedFailuresThreshold: 4,
      repeatedFailuresWindowMinutes: 10
    }
  },
  {
    id: 'RULE-002',
    name: 'Burst of Failures Followed by Success',
    category: 'BURST_FAILURE_THEN_SUCCESS',
    description: 'Detects multiple authentication failures followed immediately by a successful authentication within a short duration. Strongly suggests credential cracking or stolen password guessing.',
    enabled: true,
    severity: 'CRITICAL',
    threatClass: 'CONFIRMED_COMPROMISE',
    baseWeight: 45,
    params: {
      burstFailuresMinCount: 3,
      burstSuccessWindowMinutes: 15
    }
  },
  {
    id: 'RULE-003',
    name: 'Horizontal Password Spraying',
    category: 'PASSWORD_SPRAY',
    description: 'Detects a single source IP attempting logins across multiple distinct usernames in a short timeframe, avoiding per-user account lockouts.',
    enabled: true,
    severity: 'HIGH',
    threatClass: 'SUSPICIOUS',
    baseWeight: 35,
    params: {
      sprayDistinctUsersMin: 3,
      sprayWindowMinutes: 20
    }
  },
  {
    id: 'RULE-004',
    name: 'Anomalous Off-Hours Login',
    category: 'UNUSUAL_TIME',
    description: 'Identifies authentications taking place outside of the user’s learned baseline hours or atypical diurnal distribution (e.g. overnight or early weekend hours).',
    enabled: true,
    severity: 'MEDIUM',
    threatClass: 'SUSPICIOUS',
    baseWeight: 20,
    params: {
      unusualTimeThresholdPercentile: 5,
      strictBusinessHoursOnly: false
    }
  },
  {
    id: 'RULE-005',
    name: 'Unfamiliar Source IP / Subnet Access',
    category: 'UNFAMILIAR_IP',
    description: 'Flags successful or attempted logins originating from IP addresses or geographic network subnets not observed in the user baseline profile.',
    enabled: true,
    severity: 'MEDIUM',
    threatClass: 'SUSPICIOUS',
    baseWeight: 25,
    params: {
      subnetMatchOnly: false
    }
  },
  {
    id: 'RULE-006',
    name: 'Sudden Host Access Expansion (Lateral Movement)',
    category: 'HOST_EXPANSION',
    description: 'Detects an account accessing one or more hosts/servers it has never historically authenticated to during the baseline period, or rapid expansion across critical assets.',
    enabled: true,
    severity: 'HIGH',
    threatClass: 'SUSPICIOUS',
    baseWeight: 35,
    params: {
      hostExpansionNewHostsThreshold: 1,
      hostExpansionWindowMinutes: 60
    }
  }
];
