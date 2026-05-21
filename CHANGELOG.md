# Changelog

All notable changes to **AD_AUDITOR** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/) and the project
follows [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-05-21

### Added
- **Deeper attack-path graph (Tier 3).**
  - Kerberos delegation edges: `AllowedToDelegate` (constrained), `AllowedToAct`
    (resource-based / RBCD) and `Unconstrained` (unconstrained delegation modelled
    as a path to the domain via coercion).
  - RPC lateral-movement edges, read-only and probed in parallel:
    `AdminTo` (local administrators via `NetLocalGroupGetMembers`, with localized
    "Administrators" group-name resolution for non-English systems) and
    `HasSession` (logon sessions via `NetWkstaUserEnum`).
  - **Weakest-edge highlighting** - the first escalation edge on each path is marked
    as the recommended break point: drawn red/thick in the visualization with a
    "break here" legend entry.
  - **Graphviz DOT export** of the attack-path subgraph ("EXPORT .DOT" button).

### Changed
- The **Extra LDAP Rules** module is now fault-isolated: every rule runs in its own
  guarded block, so a missing optional container or partition (e.g. AuthN Policy
  Configuration, legacy DNS location, Password Settings Container) no longer aborts
  the whole module - it logs a `skipped` note and continues.

### Fixed
- `E-NoAuthSilo` is now reported correctly when the authentication-policy-silo
  container is absent (which itself means no silos are defined).
- A single failing optional-container query no longer prevents the remaining
  Extra-LDAP findings (`E-WeakPso`, `E-Adidns`, `E-DnsWildcard`, ...) from running.

## [1.0.0] - 2026-05-20

### Added
- Initial release of AD_AUDITOR - an Active Directory security auditing suite with a
  terminal-style WPF interface (.NET Framework 4.8).
- **~110 read-only security checks** across four risk domains (Stale Objects,
  Privileged Accounts, Trusts, Anomalies) with per-domain and global risk scores
  (0-100).
- **Tier 1 (LDAP):** dormant/weak accounts, privileged group membership, Kerberoasting
  and AS-REP roasting, krbtgt/built-in admin age, delegation (unconstrained /
  constrained / RBCD), ACL attack indicators (GenericAll, WriteDacl/Owner,
  ForceChangePassword, AddMember, Shadow Credentials, LAPS/gMSA readers, OU and
  GPO-link control), DCSync and AdminSDHolder analysis, AD CS misconfigurations
  (ESC1-ESC5, ESC9, ESC13, ESC15), trusts, password/PSO policy, machine account
  quota, anonymous LDAP, sIDHistory, PrivExchange, Azure AD Connect, ADIDNS, GPO
  hygiene and SYSVOL secrets (cpassword, logon scripts, Restricted Groups).
- **Tier 2 (RPC / registry / HTTP):** host hardening on domain controllers and member
  servers - SMB signing, SMBv1, NTLM level, WDigest, LSA protection, LDAP signing and
  channel binding, Print Spooler exposure, OS build; AD CS host checks ESC7 (CA roles)
  and ESC8 (web enrollment).
- **Tier 3:** attack-path graph (membership + ACL + DCSync) computing the shortest
  privilege-escalation path from any non-privileged principal to a tier-0 target,
  excluding legitimate administrators.
- **Interactive graph visualization:** layered layout by distance to tier-0,
  colour-coded nodes (target / broad / entry / intermediate), pan and zoom, custom
  window chrome.
- **Terminal UI:** custom title bar with a red 1px window border, themed thin
  scrollbars and tooltips, live streaming console log, findings grid with per-finding
  details (affected objects, rationale, recommendation), and risk-score panels.
- **Reports:** self-contained HTML report and CSV export.
- English and Russian README files.
