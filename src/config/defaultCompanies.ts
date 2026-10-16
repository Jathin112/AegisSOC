import { CompanyAccessConfig } from '../types';

export const DEFAULT_COMPANIES: CompanyAccessConfig[] = [
  {
    id: 'COMP-001',
    name: 'Apex Financial Holdings',
    code: 'APEX-FIN',
    status: 'ACTIVE',
    validUntil: '2027-12-31',
    contactEmail: 'security-team@apexfin.example.com',
    maxSeats: 25,
    socAnalystAccess: true,
    allowedSubnets: ['10.200.0.0/16', '192.168.10.0/24'],
    description: 'Tier-1 Banking & Financial Services Client. Dedicated SOC monitoring tier.',
    updatedAt: new Date().toISOString()
  },
  {
    id: 'COMP-002',
    name: 'Nexus BioHealth Systems',
    code: 'NEXUS-BIO',
    status: 'ACTIVE',
    validUntil: '2027-06-30',
    contactEmail: 'secops@nexusbio.example.org',
    maxSeats: 15,
    socAnalystAccess: true,
    allowedSubnets: ['172.16.0.0/16'],
    description: 'Healthcare & Clinical Research enterprise. HIPAA compliance monitoring.',
    updatedAt: new Date().toISOString()
  },
  {
    id: 'COMP-003',
    name: 'Vanguard Aerospace Labs',
    code: 'VANGUARD-AERO',
    status: 'ACTIVE',
    validUntil: '2026-11-30',
    contactEmail: 'ciso@vanguardlabs.example.net',
    maxSeats: 10,
    socAnalystAccess: true,
    allowedSubnets: ['192.168.50.0/24'],
    description: 'Defense & Aerospace contractor. High-scrutiny lateral movement detection.',
    updatedAt: new Date().toISOString()
  },
  {
    id: 'COMP-004',
    name: 'Legacy Cloud Logistics (Suspended)',
    code: 'LEGACY-LOG',
    status: 'SUSPENDED',
    validUntil: '2026-08-15',
    contactEmail: 'admin@legacylogistics.example.com',
    maxSeats: 5,
    socAnalystAccess: false,
    allowedSubnets: ['10.50.0.0/16'],
    description: 'Supply chain contractor. Access revoked pending contract renewal.',
    updatedAt: new Date().toISOString()
  }
];
