# AegisSOC // Offline Authentication Log Forensics & Threat Detection Platform

**AegisSOC** is a high-performance, air-gapped, offline security operations center (SOC) log-analysis application. It ingests enterprise authentication logs in CSV format and identifies sophisticated intrusion patterns without relying on live systems, SaaS agents, or external network lookups.

Designed in accordance with corporate enterprise SOC ergonomics: a clean, high-contrast slate gray and white palette, zero flashy neon or distracting gradients, and structured forensic triage workflows.

---

## Key System Capabilities

### 1. Offline Ingestion & Timestamp Normalization
- **Air-Gapped Operation:** Operates 100% locally with zero external network dependencies or telemetry leakage.
- **Multi-Format Datetime Normalizer:** Automatically parses and standardizes diverse log formats:
  - ISO-8601 (`YYYY-MM-DDTHH:mm:ss.sssZ`)
  - Syslog / SQL (`YYYY-MM-DD HH:mm:ss`, `YYYY/MM/DD`)
  - US & European formats (`MM/DD/YYYY HH:mm:ss AM/PM`, `DD/MM/YYYY`)
  - Unix Epoch timestamps (both seconds and milliseconds).
- **Canonical UTC Transformation:** Converts all disparate timestamps to a unified UTC timeline for timeline correlation.

### 2. Deterministic Deduplication
- Calculates a 32-bit FNV-1a fingerprint hash (`EVT-XXXXXXXX`) across normalized event fields: `timestamp | user | ip | host | action | reason`.
- Automatically suppresses redundant retransmissions, tracks duplication counts (e.g. `x2`), and reports exact suppression percentages.

### 3. Per-User Behavioral Baseline Learning
- **Declared Training Window:** Configurable training window (percentage-based, date range, or first N days).
- **Learned Dimensions:**
  - **Diurnal Login Hours:** Learns habitual working hours (00:00–23:00 UTC distribution histogram).
  - **Habitual IPs & CIDR Subnets:** Whitelists corporate IP addresses and `/24` subnets.
  - **Authorized Host Mapping:** Whitelists workstations, jump hosts, and production servers habitually accessed by the user.

### 4. Transparent Anomaly Detection Rules Engine
Configured in a separate, editable configuration profile ([defaultRules.ts](file:///c:/Users/Jathin/Missionathon/src/config/defaultRules.ts)) with JSON import/export capability:

| Rule Category | Detection Logic | Threat Classification |
|---|---|---|
| **Repeated Failures** | $\ge N$ consecutive authentication failures on a single user or host within a sliding window (e.g. $\ge 4$ failures in 10 mins). | Suspicious Indication |
| **Burst Failures &rarr; Success** | Multiple failed attempts immediately followed by a SUCCESSFUL login within window. Indicates cracked credentials or brute-force success. | **Confirmed Compromise** |
| **Horizontal Password Spray** | Single source IP targeting $\ge N$ distinct accounts within window with high failure ratios. | Suspicious Indication |
| **Unusual Login Time** | Successful authentication during hours where the user had 0% activity during the training baseline. | Suspicious Indication |
| **Unfamiliar IP / Subnet** | Logins originating from an IP or subnet not present in the user's historical baseline profile. | Suspicious Indication |
| **Lateral Host Expansion** | User successfully authenticating to assets they have never historically accessed (e.g. Domain Controller, Vault). | Suspicious Indication |

### 5. Risk Scoring & Incident Aggregation
- **Risk Score (0–100):** Transparent multi-factor compounding formula:
  $$\text{Risk Score} = \min\left(100, \left(\sum \text{Rule Weights}\right) \times \text{Compounding Factor} + \text{Evidence Factor}\right)$$
- **Severity Levels:** Low (0–34), Medium (35–59), High (60–79), Critical (80–100).
- **Compromise Categorization:**
  - **Suspicious Indication:** Isolated deviations or early-stage reconnaissance.
  - **Confirmed Compromise:** Successful entry following brute-force, or multi-vector attack spanning credential spray and critical domain controller takeover.
- **Interactive SOC Triage Checklist:** Actionable step-by-step containment procedures (Kerberos TGT revocation, SAML token invalidation, firewall perimeter IP blocks, host isolation, and EDR inspection).
- **Analyst Audit Journal:** Record timestamped findings and analyst notes.

### 6. Enterprise Multi-Tenant Access Control
- Admins can provision client companies (e.g. Apex Financial, Nexus BioHealth, Vanguard Aerospace).
- **Access Validity Expiration Dates:** Set exact cut-off dates when client access turns off automatically.
- **Immediate Revocation Switch:** Turn tenant access ON or OFF (Suspended) with a single click.
- **Enterprise Lockout Banner:** Automatically restricts access and alerts analysts when an unauthorized or expired tenant is selected.

### 7. Exporting Reports
- **Structured CSV Export:** Export all correlated incident rows, scores, affected hosts, IPs, and triage procedures.
- **Offline HTML Forensic Dossier:** Standalone, print-ready HTML dossier with executive summary cards, incident detail panels, evidence tables, triage checklist, and analyst sign-off signature blocks.

---

## Quickstart & Verification

### Running the Local Development Server
```powershell
npm run dev
```
Navigate to `http://127.0.0.1:5173/` in any modern web browser.

### Running Engine Integration Tests
```powershell
npm run test:engine
```
Validates the entire pipeline: ingestion &rarr; deduplication &rarr; baseline learner &rarr; detection rules &rarr; scoring &rarr; export generation.

### Building for Production
```powershell
npm run build
```
Produces optimized static client assets in `dist/`.

---

## Mission Context Architecture: False-Positive Mitigation & Context-Aware Scoring

### 1. Context-Aware Detection Model
Standard statistical anomaly detection suffers from heavy alert fatigue due to authorized operational events:
- **Mass Endpoint Access during Maintenance:** IT helpdesk technicians connecting to tens of employee workstations to deploy urgent security patches or configuration changes.
- **Traveling Employees:** Sales directors and executives authenticating from unfamiliar foreign hotel IPs through corporate VPN gateways.

AegisSOC introduces three contextual layers:
1. **Declared Maintenance Windows (`MaintenanceWindow`):** Approved change windows tied to Change Advisory Board (CAB) ticket references, strict UTC start/end timestamps, approved roles (`HELPDESK`), and host pattern scopes (`ALL_WORKSTATIONS`, `WKSTN-*`).
2. **Account Role Registry (`UserAccountConfig`):** Distinguishes `HELPDESK`, `SYSADMIN`, and `REGULAR_USER` roles.
3. **Corporate VPN Gateway Profile (`CompanyVpnConfig`):** Whitelists official enterprise VPN pools (`10.250.0.0/16`, `VPN-GW01`) requiring multi-factor authentication (MFA).

---

### 2. Quantitative Impact of Contextual Rules

| Metric | Without Context (Naive Anomaly Detection) | With AegisSOC Contextual Rules | Net Change |
|---|---|---|---|
| **Helpdesk Multi-Host Alerts** | 5 Critical Host Expansion Alerts | **0 False Positives** (Tagged as `BENIGN_MAINTENANCE`, Score: 8/100) | **-100% False Positives** |
| **Traveling Staff VPN Logins** | Flagged as High Severity Unfamiliar Foreign IP | **0 False Positives** (Recognized as MFA-Verified Corporate Traveler) | **-100% False Positives** |
| **Rogue Admin / Compromised Account** (`dave.admin` accessing DC01 & Vault) | Flagged as Critical Lateral Movement | **Retained as Critical Confirmed Compromise** (Score: 95/100) | **100% True Positive Retention** |
| **External Credential Cracking** (`sarah.jenkins` Bucharest IP burst) | Flagged as Confirmed Compromise | **Retained as Critical Confirmed Compromise** (Score: 100/100) | **100% True Positive Retention** |

---

### 3. Remaining Uncertainties & Residual Risks

While contextual rules eliminate operational false alarms, security teams must be aware of specific residual uncertainties:
1. **Compromised VPN Credentials vs. Legitimate Travel:**
   - *Risk:* An adversary with stolen employee credentials and an intercepted session token connecting through the corporate VPN gateway will appear as an approved traveler.
   - *Mitigation:* AegisSOC correlates subsequent internal behavior (e.g., accessing domain controllers or unapproved file shares) and enforces impossible travel time checks.
2. **Helpdesk Account Hijacking during Active Maintenance Windows:**
   - *Risk:* If a Helpdesk account is compromised during an active maintenance window, the attacker could exploit the window to access workstations with reduced alert thresholds.
   - *Mitigation:* AegisSOC verifies asset scope boundaries. If a Helpdesk account accesses critical Tier-0 infrastructure (e.g. `DC01`, `VAULT-SRV`) even inside a maintenance window, the suppression is automatically bypassed, elevating the incident to Critical Confirmed Compromise.
3. **Emergency Unscheduled Changes (Missing CAB Ticket):**
   - *Risk:* Genuine emergency operational fixes performed outside declared maintenance windows will still trigger alerts.
   - *Mitigation:* Analysts can declare retroactive ad-hoc maintenance windows in the **Maintenance & Context** dashboard or mark the incident as `BENIGN_MAINTENANCE` in the triage audit journal.

