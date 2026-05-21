using System;
using System.Collections.Generic;
using System.DirectoryServices;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Membership and hygiene of high-privilege groups and crown-jewel accounts.
    public sealed class PrivilegedChecks : ICheck
    {
        public string Name => "Privileged Accounts";

        private const string InChain = "1.2.840.113556.1.4.1941"; // LDAP_MATCHING_RULE_IN_CHAIN

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string baseDn = ctx.DefaultNamingContext;
            string rootDn = ctx.RootDomainNamingContext;
            string rootSid = GetSid(ctx, rootDn);
            string domSid = ctx.DomainSid?.Value;

            var kerberoast = new Finding("P-PrivKerberoast", Category.PrivilegedAccounts, Severity.Critical, 20,
                "Privileged accounts are Kerberoastable (have an SPN)")
                .Why("A user-class account with an SPN can be Kerberoasted; if it is privileged, cracking its password yields domain-level access.")
                .Fix("Remove SPNs from privileged users or move them to gMSA with long random passwords.");

            var noPreauth = new Finding("P-PrivNoPreauth", Category.PrivilegedAccounts, Severity.Critical, 20,
                "Privileged accounts allow Kerberos pre-auth to be skipped (AS-REP roastable)")
                .Why("DONT_REQ_PREAUTH lets anyone request an AS-REP and crack it offline.")
                .Fix("Re-enable Kerberos pre-authentication for these accounts.");

            var disabledPriv = new Finding("P-DisabledPriv", Category.PrivilegedAccounts, Severity.Medium, 8,
                "Disabled accounts remain in privileged groups")
                .Why("Disabled privileged accounts can be re-enabled by an attacker who gains lesser rights.")
                .Fix("Remove disabled accounts from privileged groups.");

            // Key SID-defined groups
            var groups = new List<(string id, string title, string sid, Severity sev, int pts, int warnCount)>
            {
                ("P-DomainAdmins", "Domain Admins members", domSid + "-512", Severity.High, 10, 5),
                ("P-EnterpriseAdmins", "Enterprise Admins members", rootSid + "-519", Severity.High, 12, 1),
                ("P-SchemaAdmins", "Schema Admins members", rootSid + "-518", Severity.Medium, 8, 0),
                ("P-Administrators", "Builtin Administrators members", "S-1-5-32-544", Severity.High, 10, 8),
                ("P-AccountOperators", "Account Operators members", "S-1-5-32-548", Severity.Medium, 8, 0),
                ("P-BackupOperators", "Backup Operators members", "S-1-5-32-551", Severity.Medium, 8, 0),
                ("P-ServerOperators", "Server Operators members", "S-1-5-32-549", Severity.Medium, 8, 0),
                ("P-PrintOperators", "Print Operators members", "S-1-5-32-550", Severity.Medium, 6, 0),
            };

            foreach (var g in groups)
            {
                if (string.IsNullOrEmpty(g.sid) || g.sid.StartsWith("-")) continue;
                string gdn = ResolveDnBySid(ctx, g.sid);
                if (gdn == null) continue;

                int count = 0;
                string memberBase = DomainNcOf(gdn);
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(memberBase,
                    "(&(|(objectClass=user)(objectClass=computer))(memberOf:" + InChain + ":=" + Escape(gdn) + "))",
                    "sAMAccountName", "userAccountControl", "servicePrincipalName", "objectClass")))
                {
                    count++;
                    string sam = CheckUtil.Sam(r);
                    long uac = AuditContext.Int64Of(r, "userAccountControl");
                    bool isUser = ContainsClass(r, "user") && !ContainsClass(r, "computer");

                    if (isUser && r.Properties.Contains("servicePrincipalName") && r.Properties["servicePrincipalName"].Count > 0)
                        CheckUtil.AddDetail(kerberoast, sam + " in " + ShortName(gdn));
                    if ((uac & (long)Uac.DontRequirePreauth) != 0)
                        CheckUtil.AddDetail(noPreauth, sam + " in " + ShortName(gdn));
                    if ((uac & (long)Uac.AccountDisabled) != 0)
                        CheckUtil.AddDetail(disabledPriv, sam + " in " + ShortName(gdn));
                }

                var sev = g.sid.EndsWith("-518") && count > 0 ? Severity.Medium : g.sev;
                var f = new Finding(g.id, Category.PrivilegedAccounts, sev,
                    count > g.warnCount ? g.pts : 0, g.title + ": " + count)
                    .Why("Every member of this group is effectively a path to domain compromise; keep it minimal.")
                    .Fix("Reduce membership to the bare minimum and review each member.");
                // re-enumerate names (cheap) for listing
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(memberBase,
                    "(&(|(objectClass=user)(objectClass=computer))(memberOf:" + InChain + ":=" + Escape(gdn) + "))",
                    "sAMAccountName")))
                    CheckUtil.AddDetail(f, CheckUtil.Sam(r));
                yield return f;
            }

            if (kerberoast.Details.Count > 0) yield return kerberoast;
            if (noPreauth.Details.Count > 0) yield return noPreauth;
            if (disabledPriv.Details.Count > 0) yield return disabledPriv;

            // ---- krbtgt password age (golden ticket window) ----
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(sAMAccountName=krbtgt)", "pwdLastSet", "sAMAccountName")))
            {
                long pls = AuditContext.Int64Of(r, "pwdLastSet");
                int age = CheckUtil.DaysSince(pls);
                if (age > 180 || age < 0)
                {
                    yield return new Finding("P-Krbtgt", Category.PrivilegedAccounts, Severity.High,
                        age > 365 ? 15 : 8, "krbtgt password is " + (age < 0 ? "of unknown age" : age + " days old"))
                        .Why("The krbtgt key signs all Kerberos tickets. A stale key keeps a stolen Golden Ticket valid indefinitely.")
                        .Fix("Rotate the krbtgt password twice (with replication wait between) at least every 6 months.")
                        .Detail("krbtgt last set: " + CheckUtil.FmtDate(pls));
                }
            }

            // ---- RODC krbtgt accounts (per-RODC Kerberos keys) ----
            var rodc = new Finding("P-RodcKrbtgt", Category.PrivilegedAccounts, Severity.Medium, 6,
                "RODC krbtgt keys not rotated")
                .Why("Each Read-Only DC has its own krbtgt key; a stale key keeps any RODC-scoped forged ticket valid longer.")
                .Fix("Rotate RODC krbtgt account passwords periodically.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectClass=user)(sAMAccountName=krbtgt_*))", "sAMAccountName", "pwdLastSet")))
            {
                long pls = AuditContext.Int64Of(r, "pwdLastSet");
                int age = CheckUtil.DaysSince(pls);
                if (age > 180 || age < 0)
                    CheckUtil.AddDetail(rodc, CheckUtil.Sam(r) + " (set: " + CheckUtil.FmtDate(pls) + ")");
            }
            if (rodc.Details.Count > 0) yield return rodc;

            // ---- built-in Administrator (RID 500) ----
            if (!string.IsNullOrEmpty(domSid))
            {
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                    "(objectSid=" + domSid + "-500)", "sAMAccountName", "pwdLastSet", "lastLogonTimestamp")))
                {
                    long pls = AuditContext.Int64Of(r, "pwdLastSet");
                    int age = CheckUtil.DaysSince(pls);
                    if (age > 365 || age < 0)
                        yield return new Finding("P-BuiltinAdmin", Category.PrivilegedAccounts, Severity.Medium, 6,
                            "Built-in Administrator password not rotated (" + (age < 0 ? "unknown" : age + " days") + ")")
                            .Why("The RID-500 account cannot be locked out and is a perennial brute-force/pass-the-hash target.")
                            .Fix("Rotate regularly, rename, and prefer LAPS-managed local admins instead.")
                            .Detail(CheckUtil.Sam(r) + " last set: " + CheckUtil.FmtDate(pls));
                }
            }

            // ---- adminCount=1 population (potential orphaned protected objects) ----
            var adminCount = new Finding("P-AdminCount", Category.PrivilegedAccounts, Severity.Low, 4,
                "Objects flagged adminCount=1")
                .Why("adminCount=1 persists after a user leaves a protected group, leaving AdminSDHolder ACLs and a misleading footprint.")
                .Fix("Review adminCount=1 accounts no longer in protected groups and reset adminCount + inheritance.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectCategory=person)(objectClass=user)(adminCount=1))", "sAMAccountName")))
                CheckUtil.AddDetail(adminCount, CheckUtil.Sam(r));
            if (adminCount.Details.Count > 0) yield return adminCount;

            // ---- DnsAdmins (members can load a DLL on the DC as SYSTEM) ----
            var dnsAdmins = new Finding("P-DnsAdmins", Category.PrivilegedAccounts, Severity.High, 12,
                "DnsAdmins members")
                .Why("DnsAdmins can make the DNS service (running on the DC) load an arbitrary DLL, yielding code execution as SYSTEM on a domain controller.")
                .Fix("Keep DnsAdmins empty; manage DNS through delegated, non-DC accounts.");
            foreach (var gr in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectClass=group)(sAMAccountName=DnsAdmins))", "distinguishedName")))
            {
                string gdn = CheckUtil.Dn(gr);
                foreach (var mr in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                    "(memberOf:" + InChain + ":=" + Escape(gdn) + ")", "sAMAccountName")))
                    CheckUtil.AddDetail(dnsAdmins, CheckUtil.Sam(mr));
            }
            if (dnsAdmins.Details.Count > 0) yield return dnsAdmins;

            // ---- Guest account (RID 501) enabled ----
            if (!string.IsNullOrEmpty(domSid))
            {
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                    "(objectSid=" + domSid + "-501)", "sAMAccountName", "userAccountControl")))
                {
                    long uac = AuditContext.Int64Of(r, "userAccountControl");
                    if ((uac & (long)Uac.AccountDisabled) == 0)
                        yield return new Finding("P-GuestEnabled", Category.PrivilegedAccounts, Severity.Medium, 8,
                            "Guest account is enabled")
                            .Why("An enabled Guest account allows unauthenticated-style access and complicates auditing.")
                            .Fix("Disable the Guest account.")
                            .Detail(CheckUtil.Sam(r));
                }
            }

            // ---- privileged accounts not protected from delegation ----
            var deleg = new Finding("P-AdminsDelegatable", Category.PrivilegedAccounts, Severity.Medium, 8,
                "Privileged accounts not marked sensitive / cannot-be-delegated")
                .Why("Without NOT_DELEGATED (or Protected Users membership) an admin's TGT can be captured via delegation and replayed.")
                .Fix("Set 'Account is sensitive and cannot be delegated' on admins and add them to Protected Users.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectCategory=person)(objectClass=user)(adminCount=1)(!" +
                LdapBit.HasFlag("userAccountControl", (long)Uac.NotDelegated) + "))", "sAMAccountName")))
                CheckUtil.AddDetail(deleg, CheckUtil.Sam(r));
            if (deleg.Details.Count > 0) yield return deleg;

            // ---- broad principals as direct members of privileged groups ----
            var broad = new Finding("P-BroadInPriv", Category.PrivilegedAccounts, Severity.Critical, 25,
                "Broad principals are members of privileged groups")
                .Why("Adding Domain Users / Authenticated Users / Everyone to an admin group effectively grants domain control to every user.")
                .Fix("Remove broad/everyone principals from privileged groups immediately.");
            string duDn = ResolveDnBySid(ctx, domSid + "-513");
            string dcDn = ResolveDnBySid(ctx, domSid + "-515");
            string[] wellKnown = { "S-1-5-11", "S-1-1-0", "S-1-5-7" };
            foreach (var pg in new[] { domSid + "-512", "S-1-5-32-544", "S-1-5-32-551",
                                       "S-1-5-32-549", "S-1-5-32-548", "S-1-5-32-550" })
            {
                if (string.IsNullOrEmpty(pg) || pg.StartsWith("-")) continue;
                string gdn = ResolveDnBySid(ctx, pg);
                if (gdn == null) continue;
                try
                {
                    using (var ge = ctx.Bind(gdn))
                    {
                        foreach (var m in ge.Properties["member"])
                        {
                            string md = m?.ToString() ?? "";
                            if (duDn != null && string.Equals(md, duDn, StringComparison.OrdinalIgnoreCase))
                                CheckUtil.AddDetail(broad, "Domain Users in " + ShortName(gdn));
                            if (dcDn != null && string.Equals(md, dcDn, StringComparison.OrdinalIgnoreCase))
                                CheckUtil.AddDetail(broad, "Domain Computers in " + ShortName(gdn));
                            foreach (var w in wellKnown)
                                if (md.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0)
                                    CheckUtil.AddDetail(broad, w + " in " + ShortName(gdn));
                        }
                    }
                }
                catch { }
            }
            if (broad.Details.Count > 0) yield return broad;

            // ---- primaryGroupID anomaly (hidden privileged membership) ----
            var primary = new Finding("P-PrimaryGroupId", Category.PrivilegedAccounts, Severity.High, 12,
                "Accounts with a privileged primaryGroupID")
                .Why("Setting primaryGroupID to a privileged RID grants membership without appearing in the group's member list - a stealthy backdoor.")
                .Fix("Reset primaryGroupID to 513 (Domain Users) and investigate how it was changed.");
            // 512 DA, 518 SA, 519 EA, 520 Group Policy Creator Owners, 521 RODC
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectCategory=person)(objectClass=user)(|(primaryGroupID=512)(primaryGroupID=518)(primaryGroupID=519)(primaryGroupID=520)))",
                "sAMAccountName", "primaryGroupID")))
                CheckUtil.AddDetail(primary, CheckUtil.Sam(r) + " (primaryGroupID=" +
                    AuditContext.Str(r, "primaryGroupID") + ")");
            if (primary.Details.Count > 0) yield return primary;

            // ---- orphaned protected groups (adminCount=1, no members) ----
            var emptyPriv = new Finding("P-EmptyPrivGroups", Category.PrivilegedAccounts, Severity.Low, 3,
                "Protected groups (adminCount=1) with no members")
                .Why("An adminCount=1 group with no members is usually a leftover; its protected status and AdminSDHolder ACLs persist needlessly.")
                .Fix("Reset adminCount and restore inheritance on groups that are no longer privileged.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectClass=group)(adminCount=1)(!(member=*)))", "sAMAccountName")))
                CheckUtil.AddDetail(emptyPriv, CheckUtil.Sam(r));
            if (emptyPriv.Details.Count > 0) yield return emptyPriv;
        }

        // ---- helpers ----

        private static bool ContainsClass(SearchResult r, string cls)
        {
            if (!r.Properties.Contains("objectClass")) return false;
            foreach (var v in r.Properties["objectClass"])
                if (string.Equals(v?.ToString(), cls, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static string GetSid(AuditContext ctx, string dn)
        {
            try
            {
                using (var e = ctx.Bind(dn))
                {
                    var b = e.Properties["objectSid"].Value as byte[];
                    if (b != null) return new System.Security.Principal.SecurityIdentifier(b, 0).Value;
                }
            }
            catch { }
            return null;
        }

        private static string ResolveDnBySid(AuditContext ctx, string sid)
        {
            // Search both default and configuration-free domain partitions for the group.
            foreach (var nc in new[] { ctx.DefaultNamingContext, ctx.RootDomainNamingContext })
            {
                if (string.IsNullOrEmpty(nc)) continue;
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(nc,
                    "(objectSid=" + sid + ")", "distinguishedName")))
                    return CheckUtil.Dn(r);
            }
            return null;
        }

        private static string DomainNcOf(string dn)
        {
            int i = dn.IndexOf("DC=", StringComparison.OrdinalIgnoreCase);
            return i >= 0 ? dn.Substring(i) : dn;
        }

        private static string ShortName(string dn)
        {
            int i = dn.IndexOf(',');
            string head = i > 0 ? dn.Substring(0, i) : dn;
            return head.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? head.Substring(3) : head;
        }

        // Escape a DN for use inside an LDAP filter value.
        private static string Escape(string dn)
        {
            return dn.Replace("\\", "\\5c").Replace("(", "\\28").Replace(")", "\\29").Replace("*", "\\2a");
        }
    }
}
