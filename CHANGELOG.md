# Changelog

All notable changes to **AD_AUDITOR** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/) and the project
follows [Semantic Versioning](https://semver.org/).

## [1.4.0] - 2026-11-26

### Added
- **dMSA / BadSuccessor** module (`M-BadSuccessor`, `M-DmsaPrecededBy`) for Windows Server 2025
  schemas. *(shipped in source after 1.3.0, first released here)*
- **AD CS host checks ESC6, ESC10 and ESC11** (`C-ESC6`, `T2-Esc10Kdc`, `T2-Esc10Schannel`,
  `C-ESC11`), DC LM-hash storage (`T2-NoLMHash`) and nonsecure DNS dynamic updates
  (`E-DnsInsecureUpdate`). *(shipped in source after 1.3.0, first released here)*
- Connection-field tooltips shown on focus. *(shipped in source after 1.3.0)*
- `X-AclGenericWrite` - non-admins with write access to all attributes of accounts/groups, and a
  matching `GenericWrite` edge in the attack-path graph.
- `P-NotProtectedUsers` - enabled admin accounts outside the Protected Users group.
- `S-Pre2kComputers` - pre-created (pre-Windows 2000) computer accounts that never logged on.
- `T-TgtDelegation` - forest trusts that allow TGT delegation.
- `V-PrivilegeRights` - GPOs granting SeDebug/SeBackup/SeRestore/SeLoadDriver/SeImpersonate/
  SeEnableDelegation and similar rights to Everyone / Authenticated Users / Domain Users.
- `V-GpoFolderWritable` - GPO folders in SYSVOL writable by non-admins.
- **JSON export** (findings, scores and attack graph) next to HTML/CSV.
- Version shown in the title bar; project version set to 1.4.0.

### Fixed
- **Inherit-only ACEs are no longer treated as rights on the object.** All ACL-based rules and
  the Tier 3 graph counted ACEs that only propagate to children (e.g. an OU delegation for user
  objects stamped onto groups, or Microsoft's PrivExchange mitigation which makes the Exchange
  `WriteDacl` ACE inherit-only) - a major source of false positives.
- AD CS: ESC2 was only reported when the template also had an enrollee-supplied subject and
  never when it lacked an EKU; it now follows the Any-Purpose / no-EKU definition. ESC9 now
  requires a client-authentication EKU. Templates not published on any CA are skipped. The
  ESC1 graph edge now starts at the principals that can actually enroll instead of always
  Authenticated Users.
- Privileged group inventory (`P-DomainAdmins` etc.) was shown as HIGH even when membership was
  within the expected size and scored 0 points; it is now INFO in that case.
- Broad-principal detection (`P-BroadInPriv`, `A-PreWin2000`) matched SIDs by substring; it now
  matches the exact foreign-security-principal object.
- `P-AdminsDelegatable` included disabled accounts and krbtgt; `A-Unconstrained`,
  `A-AsrepRoast` and the graph's unconstrained edges included disabled accounts.
- Logon/startup scripts were never found: `scripts.ini` keys are numbered (`0CmdLine=`).
- `V-GppPassword` missed files that contained one empty and one real `cpassword`.
- SYSVOL is now read through the server/IP given in the UI, so it works when DNS does not
  resolve the domain.
- LAPS: readers and coverage only looked at legacy LAPS when both legacy and Windows LAPS
  schemas were present; coverage also listed read-only DCs.
- Trusts: `T-Rc4Trust` relied on a flag that only applies to MIT realms - it now reads the
  trust's supported encryption types. SID-filtering and selective-authentication checks now
  only apply to trusts where this domain trusts the partner, ignore MIT realms, and also flag
  forest trusts with SID history enabled.
- Host checks: SMBv1 was reported on every modern server where the `SMB1` value is simply
  absent (SMB1 is not installed by default from Server 2019); `T2-NoLMHash` was reported when
  the value is absent although LM hashes are not stored by default. ESC10 text now notes that
  DCs with the September 2025 update always enforce strong certificate binding.
- Read-only DCs were missing from DC host checks although the code claimed to include them,
  and were probed as member servers instead.
- Password policy history was flagged below 12 while recommending 24; the threshold is now 24.
- Domain functional level 10 is shown as Windows Server 2025; Windows 10 outside LTSC is
  reported as end-of-life (support ended 2025-10-14).
- DNS nonsecure-update flag read 4 bytes instead of the 1-byte value; ForestDnsZones zones were
  not scanned.
- LDAP connections leaked: the search root of every query was never disposed.
- `ServerBind` is no longer passed for serverless binds.
- CSV export neutralises leading `= + - @` to prevent spreadsheet formula injection from
  directory data.
- CSV/JSON/Graph buttons stayed enabled while a new audit was running.
- Lab scripts: `Seed-LabVulns.ps1` used a `testuser` account it never created, hard-coded
  `lab.local`, and its `-Cleanup` did not revoke the ACEs, template write or Pre-Windows 2000
  change it made; `$pwd` shadowed the automatic `$PWD`. `Harden-Lab.ps1` now also covers
  ForestDnsZones and warns that removing ADIDNS create rights stops DNS self-registration.

### Changed
- README (EN/RU): real rule count (128 instead of "~110"), the full ESC list, which checks use
  the typed credentials and which use the Windows session, which host checks run on DCs vs
  member servers, and a project layout section.

## [1.3.0] - 2026-05-21

### Added
- **Attack-path graph: BloodHound-style escalation vectors as edges.** Kerberoast and
  AS-REP roasting (`Authenticated Users -> account`) and AD CS ESC1
  (`Authenticated Users -> domain`) are folded into the Tier 3 graph, so credential-theft
  vectors now appear as paths, not just findings.
- **Expanded tier-0 target set** where membership/control itself equals DC compromise:
  Account/Server/Print/Backup Operators, DnsAdmins, and domain controller computer
  objects. This surfaces multi-hop paths such as
  `Authenticated Users -[Kerberoast]-> svc -[AllowedToDelegate]-> DC` or
  `Domain Users -[MemberOf]-> Backup Operators`.

### Changed
- **The graph now renders the full escalation subgraph** - the union of every path from a
  non-privileged entry point to tier-0 - instead of a single shortest path per source.
  Parallel edges between a pair collapse to the strongest type, and legitimate admins
  (e.g. built-in Administrator) are kept out by forward-traversing only from real entry points.
- **AD CS ESC checks gated on real enrollment rights.** ESC1/ESC2/ESC3/ESC9/ESC15 now
  flag a template only when a non-privileged principal can actually enroll in it
  (Certificate-Enrollment / AutoEnroll right or full control).

### Fixed
- Removed ESC false positives on default CA templates, which are configured with
  enrollee-supplied subject etc. but are only enrollable by administrators.

## [1.2.0] - 2026-05-21

### Added
- **Separate IP address field** in the connection bar. When set, the LDAP connection
  goes straight to that DC IP (DNS-independent) while the DC/DOMAIN field is kept as
  the domain label - useful when DNS does not resolve the domain.

### Fixed
- **Full Control (GenericAll) detection corrected.** `ActiveDirectoryRights.GenericAll`
  is a composite mask that also covers ordinary read bits (ReadControl/ReadProperty),
  so the previous `(rights & GenericAll) != 0` test matched harmless read ACEs. All
  checks now require the complete mask (`CheckUtil.FullControl`). This removes large
  numbers of false positives in `X-DCSync`, `X-AdminSDHolder`, `X-AclGenericAll`,
  `X-AclOuControl`, `G-GpoWritable` and the Tier 3 graph - a freshly promoted default
  domain now yields a clean baseline instead of dozens of phantom findings (including
  a false `T3-BroadToTier0`).

### Changed
- **Expanded the built-in / default-principal exclusion list** so default AD
  delegations are not flagged: Cert Publishers, Group Policy Creator Owners,
  Pre-Windows 2000 Compatible Access, Windows Authorization Access Group,
  Distributed COM Users, IIS_IUSRS, RODC password-replication groups,
  LocalService/NetworkService and others.

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
