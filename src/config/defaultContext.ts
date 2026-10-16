import { UserAccountConfig, MaintenanceWindow, CompanyVpnConfig } from '../types';

export const DEFAULT_USER_ACCOUNTS: UserAccountConfig[] = [
  {
    username: 'helpdesk.alex',
    role: 'HELPDESK',
    department: 'Enterprise IT Helpdesk',
    isAuthorizedHelpdesk: true,
    isApprovedTraveler: false,
    notes: 'Authorized technician for remote endpoint triage and multi-workstation maintenance during declared change windows.'
  },
  {
    username: 'helpdesk.sam',
    role: 'HELPDESK',
    department: 'IT Desktop Support',
    isAuthorizedHelpdesk: true,
    isApprovedTraveler: false,
    notes: 'Authorized desktop administrator for emergency workstation diagnostics.'
  },
  {
    username: 'alice.m',
    role: 'REGULAR_USER',
    department: 'Global Business Development',
    isAuthorizedHelpdesk: false,
    isApprovedTraveler: true,
    notes: 'Executive sales director with declared international business travel across APAC & EMEA. Authenticates via Corporate VPN with hardware MFA token.'
  },
  {
    username: 'sarah.jenkins',
    role: 'REGULAR_USER',
    department: 'Corporate Finance',
    isAuthorizedHelpdesk: false,
    isApprovedTraveler: false,
    notes: 'Financial controller. Workstation fixed to Austin HQ campus.'
  },
  {
    username: 'dave.admin',
    role: 'SYSADMIN',
    department: 'SecOps Infrastructure',
    isAuthorizedHelpdesk: false,
    isApprovedTraveler: false,
    notes: 'Privileged identity admin. Subject to strict scrutiny on Domain Controllers and Vault assets.'
  },
  {
    username: 'bob.k',
    role: 'REGULAR_USER',
    department: 'Logistics Operations',
    isAuthorizedHelpdesk: false,
    isApprovedTraveler: false,
    notes: 'Logistics dispatcher.'
  },
  {
    username: 'charlie.tech',
    role: 'REGULAR_USER',
    department: 'Software Engineering',
    isAuthorizedHelpdesk: false,
    isApprovedTraveler: false,
    notes: 'Backend developer.'
  }
];

export const DEFAULT_MAINTENANCE_WINDOWS: MaintenanceWindow[] = [
  {
    id: 'MW-2026-10-14-01',
    name: 'Bi-Weekly Workstation Security Patching & Endpoint Diagnostic',
    startTime: '2026-10-14T02:00:00.000Z',
    endTime: '2026-10-14T05:00:00.000Z',
    startEpochMs: new Date('2026-10-14T02:00:00.000Z').getTime(),
    endEpochMs: new Date('2026-10-14T05:00:00.000Z').getTime(),
    approvedAccounts: ['helpdesk.alex', 'helpdesk.sam'],
    approvedRoles: ['HELPDESK'],
    targetScope: ['ALL_WORKSTATIONS', 'WKSTN-*', 'FINANCE-*', 'PORTAL-*'],
    changeTicket: 'CHG-9842',
    description: 'Scheduled remote maintenance window approved by Change Advisory Board (CAB) for mass workstation OS patching and EDR configuration.',
    status: 'ACTIVE'
  },
  {
    id: 'MW-2026-10-16-02',
    name: 'Scheduled Server Cluster Firmware Upgrade',
    startTime: '2026-10-16T01:00:00.000Z',
    endTime: '2026-10-16T04:00:00.000Z',
    startEpochMs: new Date('2026-10-16T01:00:00.000Z').getTime(),
    endEpochMs: new Date('2026-10-16T04:00:00.000Z').getTime(),
    approvedAccounts: ['*'],
    approvedRoles: ['SYSADMIN', 'HELPDESK'],
    targetScope: ['DEV-SRV*', 'APP-SRV*'],
    changeTicket: 'CHG-9855',
    description: 'Standard maintenance window for non-production server maintenance.',
    status: 'SCHEDULED'
  }
];

export const DEFAULT_VPN_CONFIGS: CompanyVpnConfig[] = [
  {
    id: 'VPN-001',
    gatewayName: 'VPN-GW01',
    ipRanges: ['10.250.0.0/16', '10.250.1.0/24'],
    gatewayIPs: ['198.51.100.250', '203.0.113.15'],
    requiresMFA: true,
    locationLabel: 'Corporate Primary VPN Gateway (MFA Verified)',
    description: 'Enterprise Cisco AnyConnect / GlobalProtect VPN pool for authorized remote and traveling staff.'
  },
  {
    id: 'VPN-002',
    gatewayName: 'CORP-REMOTE-SSL',
    ipRanges: ['172.20.0.0/16'],
    gatewayIPs: ['198.51.100.251'],
    requiresMFA: true,
    locationLabel: 'Global Traveling Executive VPN Hub',
    description: 'Designated high-assurance VPN gateway for travelling personnel with hardware token MFA.'
  }
];
