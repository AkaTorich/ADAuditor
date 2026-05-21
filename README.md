<p align="center">
  <img src="screenshot.png" alt="AD_AUDITOR" width="900">
</p>

<h1 align="center">AD_AUDITOR</h1>

<p align="center">Active Directory security auditing suite with a terminal-style interface.</p>

<p align="center"><a href="README.ru.md">Русская версия</a></p>

---

**AD_AUDITOR** is a desktop tool for assessing the security posture of an Active Directory domain. It connects to the directory, runs a broad battery of read-only checks, scores the findings, and presents them in a hacker-terminal-style interface — including an interactive attack-path graph.

## Features

- **~110 security checks** across the whole AD attack surface, grouped into four risk domains (Stale Objects, Privileged Accounts, Trusts, Anomalies) with a per-domain and a global risk score (0–100).
- **Account & hygiene**: dormant and never-used accounts, passwords that never expire, accounts with no password required, reversible/DES encryption, legacy operating systems, stale machine passwords.
- **Privileged accounts**: membership of every sensitive group, Kerberoastable and AS-REP-roastable admins, krbtgt and built-in administrator age, DnsAdmins, enabled Guest, broad principals (e.g. Domain Users) inside admin groups, hidden membership via primaryGroupID.
- **Kerberos & delegation**: unconstrained, constrained and resource-based delegation, Kerberoasting, AS-REP roasting.
- **ACL attack indicators**: who — other than admins — can take over accounts/groups, reset passwords, modify membership, write Shadow Credentials, read LAPS/gMSA secrets, or control OUs and GPO links.
- **AD Certificate Services**: ESC1–ESC5, ESC7, ESC8, ESC9, ESC13, ESC15 misconfigurations.
- **Trusts**: SID-filtering, selective authentication, RC4, trust password age.
- **Domain & policy**: password policy, fine-grained (PSO) policies, machine account quota, anonymous LDAP, LAPS coverage, sIDHistory, Kerberos ticket lifetimes, PrivExchange, Azure AD Connect, ADIDNS spoofing, authentication policy silos, GPO hygiene and SYSVOL secrets (cpassword, logon scripts, Restricted Groups).
- **Host hardening** (over RPC, read-only): SMB signing, SMBv1, NTLM level, WDigest, LSA protection, LDAP signing & channel binding, Print Spooler exposure, and OS build — on domain controllers and member servers (probed in parallel).
- **Attack-path graph (Tier 3)**: builds a control graph and finds the shortest privilege-escalation path from any ordinary account to a domain-admin tier, with a colour-coded, zoomable, pannable node-link visualization.
- **Reports**: self-contained HTML report and CSV export for pipelines.

## Usage

1. Run the application on a domain-joined Windows machine.
2. Leave **DC/DOMAIN**, **USER** and **PASS** empty to audit the current domain with your current credentials, or specify a domain controller / domain name and an optional `DOMAIN\user` + password.
3. Press **EXECUTE** and watch the live console as each module runs.
4. Review findings in the table; select any row to inspect the affected objects, the reason it matters, and the recommended fix.
5. Open the **GRAPH** view for attack paths, or export the results with **HTML** / **CSV**.

## Requirements & notes

- Windows with the .NET Framework 4.8 runtime.
- Any standard domain user account is enough for the directory checks — domain-admin rights are **not** required.
- Host-hardening checks read each server's registry over the **Remote Registry** service and use the **current Windows session** credentials (not the credentials typed in the UI); where a host is unreachable, those checks are simply skipped.
- All checks are **read-only**. The tool never modifies the directory and never performs active exploitation.

## Disclaimer

This tool is intended for **authorized security assessment of your own environment** only. Use it only where you have explicit permission.
