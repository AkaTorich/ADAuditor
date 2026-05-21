using System.Collections.Generic;
using System.DirectoryServices;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Domain-wide policy and configuration weaknesses.
    public sealed class AnomalyChecks : ICheck
    {
        public string Name => "Anomalies / Misconfig";

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string baseDn = ctx.DefaultNamingContext;

            // ---- domain object: password policy + machine account quota ----
            using (var dom = ctx.Bind(baseDn))
            {
                int minLen = AuditContext.ParseInt(AuditContext.Str(dom, "minPwdLength"));
                int history = AuditContext.ParseInt(AuditContext.Str(dom, "pwdHistoryLength"));
                int lockout = AuditContext.ParseInt(AuditContext.Str(dom, "lockoutThreshold"));
                long maxAge = AuditContext.ToInt64(dom.Properties["maxPwdAge"].Value);
                int props = AuditContext.ParseInt(AuditContext.Str(dom, "pwdProperties"));
                var pp = (PwdProperties)props;

                var pol = new Finding("A-PasswordPolicy", Category.Anomalies, Severity.Medium, 0,
                    "Default domain password policy weaknesses")
                    .Why("A weak default policy makes spraying and offline cracking far easier across the whole domain.")
                    .Fix("Min length >= 12-14, complexity on, lockout enabled, history >= 24.");
                int pts = 0;
                if (minLen < 12) { CheckUtil.AddDetail(pol, "minPwdLength = " + minLen + " (recommend >= 12)"); pts += 8; }
                if ((pp & PwdProperties.Complex) == 0) { CheckUtil.AddDetail(pol, "password complexity DISABLED"); pts += 8; }
                if (lockout == 0) { CheckUtil.AddDetail(pol, "account lockout DISABLED (threshold = 0)"); pts += 8; }
                if (CheckUtil.IntervalToDays(maxAge) == 0) { CheckUtil.AddDetail(pol, "maxPwdAge = never expires"); pts += 4; }
                if (history < 12) { CheckUtil.AddDetail(pol, "pwdHistoryLength = " + history + " (recommend >= 24)"); pts += 4; }
                pol.Points = pts;
                if (pol.Details.Count > 0) yield return pol;

                if ((pp & PwdProperties.StoreCleartext) != 0)
                    yield return new Finding("A-DomainReversible", Category.Anomalies, Severity.High, 15,
                        "Domain stores passwords with reversible encryption")
                        .Why("Every password in the domain becomes recoverable in cleartext.")
                        .Fix("Disable the reversible-encryption flag in the Default Domain Policy and reset passwords.");

                string maq = AuditContext.Str(dom, "ms-DS-MachineAccountQuota");
                int quota = AuditContext.ParseInt(maq);
                if (quota > 0)
                    yield return new Finding("A-MachineAccountQuota", Category.Anomalies, Severity.Medium, 8,
                        "ms-DS-MachineAccountQuota = " + quota + " (any user can join machines)")
                        .Why("A non-zero quota lets any authenticated user create computer objects, enabling RBCD and noPac-style attacks.")
                        .Fix("Set ms-DS-MachineAccountQuota to 0 and delegate machine joins explicitly.")
                        .Detail("Current value: " + quota);
            }

            // ---- functional level ----
            if (ctx.DomainFunctionality < 7)
                yield return new Finding("A-FunctionalLevel", Category.Anomalies, Severity.Low, 4,
                    "Domain functional level is " + FlName(ctx.DomainFunctionality))
                    .Why("Older functional levels lack modern protections (e.g. PKINIT/Kerberos hardening, gMSA, claims).")
                    .Fix("Raise the functional level once all DCs are upgraded.")
                    .Detail("domainFunctionality = " + ctx.DomainFunctionality);

            // ---- sIDHistory present ----
            var sidHist = new Finding("A-SidHistory", Category.Anomalies, Severity.Medium, 8,
                "Accounts carrying sIDHistory")
                .Why("sIDHistory grants the rights of the referenced SID; attackers inject privileged SIDs here to hide persistence.")
                .Fix("Audit every sIDHistory entry; clear stale migration SIDs.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(sIDHistory=*)", "sAMAccountName")))
                CheckUtil.AddDetail(sidHist, CheckUtil.Sam(r));
            if (sidHist.Details.Count > 0) yield return sidHist;

            // ---- dsHeuristics anonymous LDAP / LDAP integrity ----
            string dsDn = "CN=Directory Service,CN=Windows NT,CN=Services," + ctx.ConfigurationNamingContext;
            Finding anonLdap = null;
            try
            {
                using (var ds = ctx.Bind(dsDn))
                {
                    string h = AuditContext.Str(ds, "dSHeuristics");
                    // 7th character == '2' enables anonymous LDAP operations
                    if (!string.IsNullOrEmpty(h) && h.Length >= 7 && h[6] == '2')
                        anonLdap = new Finding("A-AnonymousLdap", Category.Anomalies, Severity.High, 12,
                            "Anonymous LDAP binds enabled (dSHeuristics)")
                            .Why("Anonymous LDAP lets unauthenticated attackers enumerate the directory.")
                            .Fix("Reset the 7th character of dSHeuristics to 0.")
                            .Detail("dSHeuristics = " + h);
                }
            }
            catch { }
            if (anonLdap != null) yield return anonLdap;

            // ---- LAPS deployment (schema attribute presence) ----
            bool lapsLegacy = SchemaHas(ctx, "ms-Mcs-AdmPwd");
            bool lapsNew = SchemaHas(ctx, "msLAPS-Password") || SchemaHas(ctx, "msLAPS-EncryptedPassword");
            if (!lapsLegacy && !lapsNew)
                yield return new Finding("A-NoLAPS", Category.Anomalies, Severity.Medium, 8,
                    "LAPS does not appear to be deployed")
                    .Why("Without LAPS, local administrator passwords are often shared/static across hosts, enabling pass-the-hash lateral movement.")
                    .Fix("Deploy Windows LAPS to randomize and rotate local admin passwords.")
                    .Detail("No LAPS schema attributes found.");
            else
            {
                // LAPS schema exists - find enabled, non-DC computers with no LAPS expiration set.
                string expAttr = lapsLegacy ? "ms-Mcs-AdmPwdExpirationTime" : "msLAPS-PasswordExpirationTime";
                var lapsCoverage = new Finding("A-LapsCoverage", Category.Anomalies, Severity.Medium, 8,
                    "Computers not covered by LAPS")
                    .Why("Hosts without a managed local admin password keep static/shared credentials - a primary lateral-movement vector.")
                    .Fix("Apply the LAPS policy to all member servers and workstations.");
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                    "(&(objectCategory=computer)(!" + LdapBit.HasFlag("userAccountControl", (long)Uac.AccountDisabled) +
                    ")(!" + LdapBit.HasFlag("userAccountControl", (long)Uac.ServerTrustAccount) +
                    ")(!(" + expAttr + "=*)))",
                    "sAMAccountName")))
                    CheckUtil.AddDetail(lapsCoverage, CheckUtil.Sam(r));
                if (lapsCoverage.Details.Count > 0) yield return lapsCoverage;
            }

            // ---- gMSA inventory (informational) ----
            var gmsa = new Finding("A-Gmsa", Category.Anomalies, Severity.Info, 0,
                "Group Managed Service Accounts present")
                .Why("gMSA is the recommended way to run services; listed for inventory.")
                .Fix("");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(objectClass=msDS-GroupManagedServiceAccount)", "sAMAccountName")))
                CheckUtil.AddDetail(gmsa, CheckUtil.Sam(r));
            if (gmsa.Details.Count > 0) yield return gmsa;

            // ---- passwords hinted in the description field ----
            var descPwd = new Finding("A-DescriptionPassword", Category.Anomalies, Severity.Medium, 8,
                "Accounts with a password hint in the description")
                .Why("Administrators often store passwords in the readable description field, exposing them to every domain user.")
                .Fix("Remove credentials from descriptions and reset the affected passwords.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectCategory=person)(objectClass=user)(|(description=*password*)(description=*passwd*)(description=*pwd=*)))",
                "sAMAccountName", "description")))
                CheckUtil.AddDetail(descPwd, CheckUtil.Sam(r) + " : " + AuditContext.Str(r, "description"));
            if (descPwd.Details.Count > 0) yield return descPwd;

            // ---- cleartext-capable password attributes ----
            var userPwd = new Finding("A-UserPasswordAttr", Category.Anomalies, Severity.High, 12,
                "Accounts with userPassword / unixUserPassword populated")
                .Why("These attributes can hold cleartext passwords readable by users with read access.")
                .Fix("Clear userPassword/unixUserPassword and use proper credential storage.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectClass=user)(|(userPassword=*)(unixUserPassword=*)))", "sAMAccountName")))
                CheckUtil.AddDetail(userPwd, CheckUtil.Sam(r));
            if (userPwd.Details.Count > 0) yield return userPwd;

            // ---- weak Kerberos encryption types (DES/RC4 only, no AES) ----
            var weakEnc = new Finding("A-WeakEncTypes", Category.Anomalies, Severity.Medium, 6,
                "Accounts restricted to weak Kerberos encryption (no AES)")
                .Why("Forcing DES/RC4 produces tickets that are far cheaper to crack and easier to forge.")
                .Fix("Enable AES (msDS-SupportedEncryptionTypes) on these accounts.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(msDS-SupportedEncryptionTypes=*)", "sAMAccountName", "msDS-SupportedEncryptionTypes")))
            {
                int et = (int)AuditContext.Int64Of(r, "msDS-SupportedEncryptionTypes");
                if (et != 0 && (et & 0x18) == 0) // no AES128 (0x8) and no AES256 (0x10)
                    CheckUtil.AddDetail(weakEnc, CheckUtil.Sam(r) + " (etypes=" + et + ")");
            }
            if (weakEnc.Details.Count > 0) yield return weakEnc;

            // ---- duplicate SPNs (Kerberos breakage / misconfiguration) ----
            var dupSpn = new Finding("A-DuplicateSpn", Category.Anomalies, Severity.Low, 4,
                "Service Principal Names registered on more than one object")
                .Why("Duplicate SPNs break Kerberos for the affected service and can indicate account takeover or misconfiguration.")
                .Fix("Ensure each SPN is unique; remove the stale registration.");
            var spnOwners = new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase);
            var spnDup = new System.Collections.Generic.HashSet<string>();
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(servicePrincipalName=*)", "sAMAccountName", "servicePrincipalName")))
            {
                string owner = CheckUtil.Sam(r);
                foreach (var v in r.Properties["servicePrincipalName"])
                {
                    string spn = v?.ToString() ?? "";
                    if (spn.Length == 0) continue;
                    if (spnOwners.TryGetValue(spn, out var first))
                    {
                        if (spnDup.Add(spn))
                            CheckUtil.AddDetail(dupSpn, spn + " : " + first + " & " + owner);
                    }
                    else spnOwners[spn] = owner;
                }
            }
            if (dupSpn.Details.Count > 0) yield return dupSpn;

            // ---- existing key credentials (Shadow Credentials artifact) ----
            var shadow = new Finding("A-ShadowCredPresent", Category.Anomalies, Severity.Medium, 6,
                "Accounts with key credentials (msDS-KeyCredentialLink) populated")
                .Why("Key credentials allow PKINIT logon for the account; unexpected entries are the hallmark of the Shadow Credentials (Whisker) attack.")
                .Fix("Confirm each entry is a legitimate Windows Hello / passwordless enrollment; remove unknown ones.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(msDS-KeyCredentialLink=*)", "sAMAccountName")))
                CheckUtil.AddDetail(shadow, CheckUtil.Sam(r));
            if (shadow.Details.Count > 0) yield return shadow;

            // ---- circular group nesting ----
            var circular = new Finding("A-CircularGroups", Category.Anomalies, Severity.Low, 4,
                "Circular group nesting detected")
                .Why("Group cycles inflate token size, can break replication/processing, and obscure effective membership.")
                .Fix("Break the membership loop between the listed groups.");
            var groupDns = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
            var adj = new System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<string>>(System.StringComparer.OrdinalIgnoreCase);
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(objectClass=group)", "distinguishedName", "member")))
            {
                string dn = CheckUtil.Dn(r);
                groupDns.Add(dn);
                var members = new System.Collections.Generic.List<string>();
                if (r.Properties.Contains("member"))
                    foreach (var m in r.Properties["member"]) members.Add(m?.ToString() ?? "");
                adj[dn] = members;
            }
            DetectCycles(adj, groupDns, circular);
            if (circular.Details.Count > 0) yield return circular;

            // ---- tombstone lifetime ----
            Finding tombstone = null;
            try
            {
                using (var ds = ctx.Bind(dsDn))
                {
                    string tl = AuditContext.Str(ds, "tombstoneLifetime");
                    int days = AuditContext.ParseInt(tl);
                    if (days > 0 && days < 180)
                        tombstone = new Finding("A-TombstoneLifetime", Category.Anomalies, Severity.Low, 4,
                            "Tombstone lifetime is only " + days + " days")
                            .Why("A short tombstone lifetime shrinks the window for forest recovery from backups.")
                            .Fix("Set tombstoneLifetime to at least 180 days.")
                            .Detail("tombstoneLifetime = " + days);
                }
            }
            catch { }
            if (tombstone != null) yield return tombstone;

            // ---- AD Recycle Bin ----
            Finding recycle = null;
            try
            {
                using (var part = ctx.Bind("CN=Partitions," + ctx.ConfigurationNamingContext))
                {
                    bool enabled = false;
                    foreach (var v in part.Properties["msDS-EnabledFeature"])
                        if ((v?.ToString() ?? "").IndexOf("Recycle Bin", System.StringComparison.OrdinalIgnoreCase) >= 0)
                            enabled = true;
                    if (!enabled)
                        recycle = new Finding("A-RecycleBin", Category.Anomalies, Severity.Low, 3,
                            "AD Recycle Bin is not enabled")
                            .Why("Without the Recycle Bin, accidentally or maliciously deleted objects are much harder to recover.")
                            .Fix("Enable the AD Recycle Bin optional feature (irreversible once enabled).");
                }
            }
            catch { }
            if (recycle != null) yield return recycle;

            // ---- Pre-Windows 2000 Compatible Access containing anonymous/everyone ----
            string pw2k = "CN=Pre-Windows 2000 Compatible Access,CN=Builtin," + baseDn;
            Finding preWin = null;
            try
            {
                using (var grp = ctx.Bind(pw2k))
                {
                    foreach (var m in grp.Properties["member"])
                    {
                        string md = m?.ToString() ?? "";
                        if (md.IndexOf("S-1-1-0", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                            md.IndexOf("S-1-5-7", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                            md.IndexOf("Everyone", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                            md.IndexOf("Anonymous", System.StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            if (preWin == null)
                                preWin = new Finding("A-PreWin2000", Category.Anomalies, Severity.High, 12,
                                    "Anonymous/Everyone in 'Pre-Windows 2000 Compatible Access'")
                                    .Why("This grants broad read access to the directory to anonymous or all users.")
                                    .Fix("Remove Anonymous Logon / Everyone from this group.");
                            preWin.Detail(md);
                        }
                    }
                }
            }
            catch { }
            if (preWin != null) yield return preWin;
        }

        // DFS cycle detection over group-to-group membership edges.
        private static void DetectCycles(
            System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<string>> adj,
            System.Collections.Generic.HashSet<string> groups,
            Finding finding)
        {
            var color = new System.Collections.Generic.Dictionary<string, int>(System.StringComparer.OrdinalIgnoreCase);
            foreach (var g in groups)
            {
                if (!color.ContainsKey(g))
                    Visit(g, adj, groups, color, finding);
            }
        }

        private static void Visit(string node,
            System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<string>> adj,
            System.Collections.Generic.HashSet<string> groups,
            System.Collections.Generic.Dictionary<string, int> color,
            Finding finding)
        {
            color[node] = 1; // in stack
            if (adj.TryGetValue(node, out var members))
            {
                foreach (var child in members)
                {
                    if (!groups.Contains(child)) continue; // only group->group edges
                    color.TryGetValue(child, out int c);
                    if (c == 1)
                        CheckUtil.AddDetail(finding, ShortDn(node) + " <-> " + ShortDn(child));
                    else if (c == 0)
                        Visit(child, adj, groups, color, finding);
                }
            }
            color[node] = 2; // done
        }

        private static string ShortDn(string dn)
        {
            int i = dn.IndexOf(',');
            string head = i > 0 ? dn.Substring(0, i) : dn;
            return head.StartsWith("CN=", System.StringComparison.OrdinalIgnoreCase) ? head.Substring(3) : head;
        }

        private static bool SchemaHas(AuditContext ctx, string attr)
        {
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(ctx.SchemaNamingContext,
                "(&(objectClass=attributeSchema)(lDAPDisplayName=" + attr + "))", "lDAPDisplayName")))
                return true;
            return false;
        }

        private static string FlName(int fl)
        {
            switch (fl)
            {
                case 0: return "Windows 2000";
                case 2: return "Windows Server 2003";
                case 3: return "Windows Server 2008";
                case 4: return "Windows Server 2008 R2";
                case 5: return "Windows Server 2012";
                case 6: return "Windows Server 2012 R2";
                case 7: return "Windows Server 2016";
                default: return "level " + fl;
            }
        }
    }
}
