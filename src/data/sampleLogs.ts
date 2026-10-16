/**
 * Realistic Enterprise Multi-Scenario Authentication Logs
 * Includes:
 * 1. Training Baseline logs (habitual hours, subnets, workstations)
 * 2. Authorised Helpdesk multi-host maintenance within declared change window (False-Positive Test)
 * 3. Legitimate travelling employee logging in through Corporate VPN (False-Positive Test)
 * 4. Suspicious host expansion by regular user outside maintenance window (True-Positive Test)
 * 5. Repeated failures & credential cracking compromise (Bucharest external IP)
 * 6. Horizontal password spraying across corporate directory (Tor exit node)
 * 7. Deduplication testing with duplicate records
 */

export const SAMPLE_CSV_LOGS = `timestamp,user,ip,host,action,reason,location
2026-10-10 08:30:15,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 09:05:00,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 09:12:30,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 09:45:10,dave.admin,10.200.0.15,SEC-ADMIN01,SUCCESS,Login successful,Corporate SecOps
2026-10-10 10:00:00,helpdesk.alex,10.200.0.88,WKSTN-HD01,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 10:15:22,charlie.tech,10.200.3.88,DEV-SRV04,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 13:00:10,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 14:20:45,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-10 17:30:00,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Logoff/Login,Internal Austin LAN

2026-10-11 08:35:00,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 08:45:12,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 09:00:20,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 09:15:33,dave.admin,10.200.0.15,SEC-ADMIN01,SUCCESS,Login successful,Corporate SecOps
2026-10-11 09:30:00,helpdesk.alex,10.200.0.88,WKSTN-HD01,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 11:20:00,charlie.tech,10.200.3.88,DEV-SRV04,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 14:10:05,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 16:55:00,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN

2026-10-12 08:32:10,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-12 08:50:40,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-12 09:05:15,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN
2026-10-12 09:20:00,dave.admin,10.200.0.15,SEC-ADMIN01,SUCCESS,Login successful,Corporate SecOps
2026-10-12 09:35:00,helpdesk.alex,10.200.0.88,WKSTN-HD01,SUCCESS,Login successful,Internal Austin LAN
2026-10-12 10:45:12,charlie.tech,10.200.3.88,DEV-SRV04,SUCCESS,Login successful,Internal Austin LAN
2026-10-12 15:10:00,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN

2026-10-13 08:40:00,alice.m,10.200.1.45,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-13 08:55:10,bob.k,10.200.1.46,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-13 09:10:05,sarah.jenkins,10.200.2.11,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN
2026-10-13 09:30:22,dave.admin,10.200.0.15,SEC-ADMIN01,SUCCESS,Login successful,Corporate SecOps
2026-10-13 09:40:00,helpdesk.alex,10.200.0.88,WKSTN-HD01,SUCCESS,Login successful,Internal Austin LAN
2026-10-13 13:15:00,charlie.tech,10.200.3.88,DEV-SRV04,SUCCESS,Login successful,Internal Austin LAN
2026-10-13 16:30:45,dave.admin,10.200.0.15,SEC-ADMIN01,SUCCESS,Login successful,Corporate SecOps

2026-10-14 01:20:10,admin,185.220.101.5,VPN-GW01,FAILURE,Bad Password,Tor Exit Node
2026-10-14 01:21:40,guest,185.220.101.5,VPN-GW01,FAILURE,Account Disabled,Tor Exit Node
2026-10-14 01:23:05,dbadmin,185.220.101.5,VPN-GW01,FAILURE,User Not Found,Tor Exit Node
2026-10-14 01:24:15,svc_backup,185.220.101.5,VPN-GW01,FAILURE,Bad Password,Tor Exit Node
2026-10-14 01:25:30,guest_support,185.220.101.5,VPN-GW01,FAILURE,Bad Password,Tor Exit Node
2026-10-14 01:26:45,bob.k,185.220.101.5,VPN-GW01,FAILURE,Bad Password,Tor Exit Node
2026-10-14 01:28:10,root,185.220.101.5,VPN-GW01,FAILURE,Bad Password,Tor Exit Node

2026-10-14 02:15:10,helpdesk.alex,10.200.0.88,WKSTN-ALICE,SUCCESS,Login successful,Internal Austin LAN
2026-10-14 02:22:30,helpdesk.alex,10.200.0.88,WKSTN-BOB,SUCCESS,Login successful,Internal Austin LAN
2026-10-14 02:35:45,helpdesk.alex,10.200.0.88,WKSTN-FINANCE01,SUCCESS,Login successful,Internal Austin LAN
2026-10-14 02:50:12,helpdesk.alex,10.200.0.88,WKSTN-CORP01,SUCCESS,Login successful,Internal Austin LAN
2026-10-14 03:10:00,helpdesk.alex,10.200.0.88,WKSTN-CORP02,SUCCESS,Login successful,Internal Austin LAN

2026-10-14 02:45:12,charlie.tech,203.0.113.88,DEV-SRV04,SUCCESS,Login successful,Sofia Bulgaria
2026-10-14 02:45:12,charlie.tech,203.0.113.88,DEV-SRV04,SUCCESS,Login successful,Sofia Bulgaria

2026-10-14 03:15:00,dave.admin,192.168.99.210,SEC-ADMIN01,SUCCESS,Privileged Logon,Unfamiliar Subnet
2026-10-14 03:22:15,dave.admin,192.168.99.210,DC01.corp.local,SUCCESS,Kerberos TGS Request,Unfamiliar Subnet
2026-10-14 03:28:40,dave.admin,192.168.99.210,VAULT-SRV,SUCCESS,SMB Session Setup,Unfamiliar Subnet
2026-10-14 03:34:10,dave.admin,192.168.99.210,FINANCE-DB02,SUCCESS,RDP Session Connect,Unfamiliar Subnet

2026-10-14 06:30:00,alice.m,10.250.1.15,VPN-GW01,SUCCESS,Login successful,Corporate Primary VPN Gateway (MFA Verified)
2026-10-14 06:35:10,alice.m,10.250.1.15,WKSTN-ALICE,SUCCESS,Login successful,Corporate Primary VPN Gateway (MFA Verified)

2026-10-14 14:10:10,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,Bad Password,Bucharest Romania
2026-10-14 14:11:20,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,Bad Password,Bucharest Romania
2026-10-14 14:12:45,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,Bad Password,Bucharest Romania
2026-10-14 14:14:02,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,MFA Challenge Failed,Bucharest Romania
2026-10-14 14:15:30,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,Bad Password,Bucharest Romania
2026-10-14 14:17:15,sarah.jenkins,198.51.100.44,PORTAL-EXT01,FAILURE,Bad Password,Bucharest Romania
2026-10-14 14:19:00,sarah.jenkins,198.51.100.44,PORTAL-EXT01,SUCCESS,Login successful,Bucharest Romania
2026-10-14 14:19:00,sarah.jenkins,198.51.100.44,PORTAL-EXT01,SUCCESS,Login successful,Bucharest Romania

2026-10-10 09:00:00,norman.normal,10.200.1.50,WKSTN-NORM,SUCCESS,Login successful,Internal Austin LAN
2026-10-11 09:05:00,norman.normal,10.200.1.50,WKSTN-NORM,SUCCESS,Login successful,Internal Austin LAN
2026-10-12 09:10:00,norman.normal,10.200.1.50,WKSTN-NORM,SUCCESS,Login successful,Internal Austin LAN
2026-10-13 09:15:00,norman.normal,10.200.1.50,WKSTN-NORM,SUCCESS,Login successful,Internal Austin LAN

2026-10-14 09:30:00,norman.normal,10.200.1.50,WKSTN-NORM,SUCCESS,Login successful,Internal Austin LAN
2026-10-14 10:00:00,victor.travel,10.200.1.77,WKSTN-VIC,SUCCESS,Login successful,Internal Austin LAN
2026-10-14 10:20:00,victor.travel,185.120.45.10,PORTAL-EXT01,SUCCESS,Login successful,London UK

2026-10-14 11:00:00,ian.uncertain,-,PORTAL-EXT01,FAILURE,Bad Password,
2026-10-14 11:05:00,ian.uncertain,UNKNOWN,PORTAL-EXT01,FAILURE,Bad Password,
2026-10-14 11:10:00,corrupt.user,999.999.999.999,WKSTN-CORP01,FAILURE,Bad Password,

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
