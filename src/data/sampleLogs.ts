/**
 * Realistic Enterprise Multi-Scenario Authentication Logs
 * Includes:
 * 1. Training Baseline logs (habitual hours, subnets, workstations)
 * 2. Repeated Failures & Credential Guessing
 * 3. Burst of Failures followed by Success (Credential Compromise)
 * 4. Horizontal Password Spray attack from external threat actor
 * 5. Sudden Host Access Expansion (Lateral Movement onto DC and Vault)
 * 6. Anomalous Off-Hours Logins from Unfamiliar IPs
 * 7. Duplicate entries to test deduplication
 */

export const SAMPLE_CSV_LOGS = `timestamp,user,ip,host,action,reason,location
2026-10-10 08:30:15,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 09:05:00,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 09:12:30,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 09:45:10,dave.admin,10.200.0.15,SEC-ADMIN01,SUCCESS,Login successful,Corporate SecOps
2026-10-10 10:15:22,charlie.tech,10.200.3.88,DEV-SRV04,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 13:00:10,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 14:20:45,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 17:30:00,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Logoff/Logon,Internal Austin LAN

2026-10-11 08:35:00,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 08:45:12,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 09:00:20,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 09:15:33,dave.admin,10.200.0.15,SEC-ADMIN01,SUCCESS,Login successful,Corporate SecOps
2026-10-11 11:20:00,charlie.tech,10.200.3.88,DEV-SRV04,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 14:10:05,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 16:55:00,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN

2026-10-12 08:32:10,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-12 08:50:40,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-12 09:05:15,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN
2026-10-12 09:20:00,dave.admin,10.200.0.15,SEC-ADMIN01,SUCCESS,Login successful,Corporate SecOps
2026-10-12 10:45:12,charlie.tech,10.200.3.88,DEV-SRV04,SUCCESS,Login successful,Internal Austin LAN
2026-10-12 15:10:00,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN

2026-10-13 08:40:00,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-13 08:55:10,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-13 09:10:05,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN
2026-10-13 09:30:22,dave.admin,10.200.0.15,SEC-ADMIN01,SUCCESS,Login successful,Corporate SecOps
2026-10-13 13:15:00,charlie.tech,10.200.3.88,DEV-SRV04,SUCCESS,Login successful,Internal Austin LAN
2026-10-13 16:30:45,dave.admin,10.200.0.15,SEC-ADMIN01,SUCCESS,Login successful,Corporate SecOps

2026-10-14 01:20:10,admin,185.220.101.5,VPN-GW01,FAILURE,Bad Password,Tor Exit Node
2026-10-14 01:21:40,guest,185.220.101.5,VPN-GW01,FAILURE,Account Disabled,Tor Exit Node
2026-10-14 01:23:05,dbadmin,185.220.101.5,VPN-GW01,FAILURE,User Not Found,Tor Exit Node
2026-10-14 01:24:15,svc_backup,185.220.101.5,VPN-GW01,FAILURE,Bad Password,Tor Exit Node
2026-10-14 01:25:30,alice.m,185.220.101.5,VPN-GW01,FAILURE,Bad Password,Tor Exit Node
2026-10-14 01:26:45,bob.k,185.220.101.5,VPN-GW01,FAILURE,Bad Password,Tor Exit Node
2026-10-14 01:28:10,root,185.220.101.5,VPN-GW01,FAILURE,Bad Password,Tor Exit Node

2026-10-14 02:45:12,charlie.tech,203.0.113.88,DEV-SRV04,SUCCESS,Login successful,Sofia Bulgaria
2026-10-14 02:45:12,charlie.tech,203.0.113.88,DEV-SRV04,SUCCESS,Login successful,Sofia Bulgaria

2026-10-14 03:15:00,dave.admin,192.168.99.210,SEC-ADMIN01,SUCCESS,Privileged Logon,Unfamiliar Subnet
2026-10-14 03:22:15,dave.admin,192.168.99.210,DC01.corp.local,SUCCESS,Kerberos TGS Request,Unfamiliar Subnet
2026-10-14 03:28:40,dave.admin,192.168.99.210,VAULT-SRV,SUCCESS,SMB Session Setup,Unfamiliar Subnet
2026-10-14 03:34:10,dave.admin,192.168.99.210,FINANCE-DB02,SUCCESS,RDP Session Connect,Unfamiliar Subnet

2026-10-14 14:10:10,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,Bad Password,Bucharest Romania
2026-10-14 14:11:20,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,Bad Password,Bucharest Romania
2026-10-14 14:12:45,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,Bad Password,Bucharest Romania
2026-10-14 14:14:02,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,MFA Challenge Failed,Bucharest Romania
2026-10-14 14:15:30,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,Bad Password,Bucharest Romania
2026-10-14 14:17:15,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,Bad Password,Bucharest Romania
2026-10-14 14:19:00,sarah.jenkins,198.51.100.44,PORTAL-EXT01,SUCCESS,Login successful,Bucharest Romania
2026-10-14 14:19:00,sarah.jenkins,198.51.100.44,PORTAL-EXT01,SUCCESS,Login successful,Bucharest Romania

2026-10-14 15:00:20,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-14 15:30:10,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
`;

export const CLEAN_BENCHMARK_CSV = `timestamp,user,ip,host,action,reason,location
2026-10-10 08:30:00,john.doe,10.100.4.12,WKSTN-CORP01,SUCCESS,Login successful,HQ Campus
2026-10-10 08:45:00,jane.smith,10.100.4.15,WKSTN-CORP02,SUCCESS,Login successful,HQ Campus
2026-10-10 09:00:00,mark.lee,10.100.4.20,WKSTN-CORP03,SUCCESS,Login successful,HQ Campus
2026-10-11 08:32:00,john.doe,10.100.4.12,WKSTN-CORP01,SUCCESS,Login successful,HQ Campus
2026-10-11 08:50:00,jane.smith,10.100.4.15,WKSTN-CORP02,SUCCESS,Login successful,HQ Campus
2026-10-12 08:35:00,john.doe,10.100.4.12,WKSTN-CORP01,SUCCESS,Login successful,HQ Campus
2026-10-12 09:05:00,mark.lee,10.100.4.20,WKSTN-CORP03,SUCCESS,Login successful,HQ Campus
`;
