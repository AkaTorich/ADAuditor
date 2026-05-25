using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Targeted, high-value LDAP rules: Exchange/PrivExchange, Azure AD Connect,
    // fine-grained password policies, ADIDNS, and authentication policy silos.
    // Each rule is isolated so a missing optional container/partition cannot abort the rest.
    public sealed class LdapExtraChecks : ICheck
    {
        public string Name => "Extra LDAP Rules";

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string baseDn = ctx.DefaultNamingContext;
            string domSid = ctx.DomainSid?.Value ?? "";
            var defaults = CheckUtil.DefaultPrivSids(domSid);

            // ---- PrivExchange: Exchange groups with dangerous rights on the domain head ----
            var privExchange = new Finding("E-PrivExchange", Category.PrivilegedAccounts, Severity.Critical, 22,
                "Exchange security groups hold dangerous rights over the domain")
                .Why("Exchange Windows Permissions / Exchange Trusted Subsystem with WriteDacl on the domain head is the PrivExchange path - relay an Exchange server's auth and grant yourself DCSync.")
                .Fix("Remove WriteDacl from Exchange groups on the domain object (apply Microsoft's split-permissions / AD hardening).");
            try
            {
                var exchangeSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var gn in new[] { "Exchange Windows Permissions", "Exchange Trusted Subsystem", "Organization Management" })
                    foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                        "(&(objectClass=group)(sAMAccountName=" + gn + "))", "objectSid")))
                    {
                        var b = CheckUtil.Bytes(r, "objectSid");
                        if (b != null) exchangeSids.Add(new SecurityIdentifier(b, 0).Value);
                    }
                if (exchangeSids.Count > 0)
                    using (var dom = ctx.Bind(baseDn))
                    {
                        dom.Options.SecurityMasks = SecurityMasks.Dacl;
                        foreach (ActiveDirectoryAccessRule rule in
                                 dom.ObjectSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                        {
                            if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                            if (!exchangeSids.Contains(rule.IdentityReference.Value)) continue;
                            var rights = rule.ActiveDirectoryRights;
                            if ((rights & ActiveDirectoryRights.WriteDacl) != 0 ||
                                (rights & ActiveDirectoryRights.WriteOwner) != 0 ||
                                CheckUtil.FullControl(rights))
                                CheckUtil.AddDetail(privExchange, CheckUtil.TranslateSid(rule.IdentityReference.Value) + " : " + rights);
                        }
                    }
            }
            catch (Exception ex) { ctx.Log?.Invoke("    [!] PrivExchange check skipped: " + ex.Message); }
            if (privExchange.Details.Count > 0) yield return privExchange;

            // ---- Azure AD Connect synchronization account ----
            var aadc = new Finding("E-AadConnect", Category.PrivilegedAccounts, Severity.High, 12,
                "Azure AD Connect synchronization account present")
                .Why("MSOL_/AAD_ accounts typically hold directory-replication (DCSync) rights; compromising the AAD Connect server yields every hash in the domain.")
                .Fix("Treat the AAD Connect server and its sync account as tier-0; protect and monitor them.");
            try
            {
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                    "(&(objectClass=user)(|(sAMAccountName=MSOL_*)(sAMAccountName=AAD_*)))",
                    "sAMAccountName", "description")))
                    CheckUtil.AddDetail(aadc, CheckUtil.Sam(r) + " : " + AuditContext.Str(r, "description"));
            }
            catch (Exception ex) { ctx.Log?.Invoke("    [!] AAD Connect check skipped: " + ex.Message); }
            if (aadc.Details.Count > 0) yield return aadc;

            // ---- fine-grained (PSO) password policies ----
            var pso = new Finding("E-WeakPso", Category.Anomalies, Severity.Medium, 8,
                "Weak fine-grained password policy (PSO)")
                .Why("A weak PSO overrides the domain policy for the principals it targets, creating a soft spot for spraying.")
                .Fix("Raise PSO minimum length/complexity/lockout to match or exceed the domain policy.");
            try
            {
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(
                    "CN=Password Settings Container,CN=System," + baseDn,
                    "(objectClass=msDS-PasswordSettings)",
                    "cn", "msDS-MinimumPasswordLength", "msDS-PasswordComplexityEnabled", "msDS-LockoutThreshold")))
                {
                    string cn = AuditContext.Str(r, "cn");
                    int minLen = AuditContext.ParseInt(AuditContext.Str(r, "msDS-MinimumPasswordLength"));
                    bool complex = string.Equals(AuditContext.Str(r, "msDS-PasswordComplexityEnabled"), "TRUE", StringComparison.OrdinalIgnoreCase);
                    int lockout = AuditContext.ParseInt(AuditContext.Str(r, "msDS-LockoutThreshold"));
                    var issues = new List<string>();
                    if (minLen < 12) issues.Add("minLen=" + minLen);
                    if (!complex) issues.Add("complexity off");
                    if (lockout == 0) issues.Add("no lockout");
                    if (issues.Count > 0)
                        CheckUtil.AddDetail(pso, cn + " (" + string.Join(", ", issues) + ")");
                }
            }
            catch (Exception ex) { ctx.Log?.Invoke("    [!] PSO check skipped: " + ex.Message); }
            if (pso.Details.Count > 0) yield return pso;

            // ---- ADIDNS: who can create DNS records, plus wildcard records ----
            var adidns = new Finding("E-Adidns", Category.Anomalies, Severity.Medium, 8,
                "AD-integrated DNS zones allow record creation by broad principals")
                .Why("If Authenticated Users can create DNS records, an attacker can plant WPAD/wildcard entries to capture and relay authentication (ADIDNS spoofing).")
                .Fix("Restrict CreateChild on sensitive zones; deploy the DNS global query block list.");
            var wildcard = new Finding("E-DnsWildcard", Category.Anomalies, Severity.Low, 4,
                "Wildcard DNS records present")
                .Why("A wildcard (*) record can be abused to answer arbitrary name lookups.")
                .Fix("Review and remove unnecessary wildcard records.");
            var dnsUpdate = new Finding("E-DnsInsecureUpdate", Category.Anomalies, Severity.Medium, 8,
                "AD-integrated DNS zones allow nonsecure dynamic updates")
                .Why("Nonsecure dynamic updates let any host (even unauthenticated) overwrite DNS records, enabling spoofing and relay.")
                .Fix("Set the zone to 'Secure only' dynamic updates.");
            foreach (var part in new[] { "DC=DomainDnsZones," + baseDn, "CN=MicrosoftDNS,CN=System," + baseDn })
            {
                try
                {
                    foreach (var z in CheckUtil.Enumerate(CheckUtil.WithDacl(ctx.SubtreeSearcher(part,
                        "(objectClass=dnsZone)", "name", "distinguishedName", "nTSecurityDescriptor", "dNSProperty"))))
                    {
                        byte[] sdb = CheckUtil.Bytes(z, "nTSecurityDescriptor");
                        string zone = AuditContext.Str(z, "name");

                        // nonsecure dynamic updates (DSPROPERTY_ZONE_ALLOW_UPDATE == 1)
                        if (z.Properties.Contains("dNSProperty"))
                            foreach (var pv in z.Properties["dNSProperty"])
                            {
                                var blob = pv as byte[];
                                if (blob == null || blob.Length < 24) continue;
                                uint id = BitConverter.ToUInt32(blob, 16);
                                if (id == 0x02 && BitConverter.ToUInt32(blob, 20) == 1)
                                    CheckUtil.AddDetail(dnsUpdate, zone + " (nonsecure updates allowed)");
                            }

                        if (sdb == null) continue;
                        ActiveDirectorySecurity sd;
                        try { sd = CheckUtil.ParseSd(sdb); } catch { continue; }
                        foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                        {
                            if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                            string sid = rule.IdentityReference.Value;
                            if (sid != "S-1-5-11" && sid != "S-1-1-0") continue; // Authenticated Users / Everyone
                            if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.CreateChild) != 0)
                                CheckUtil.AddDetail(adidns, zone + " : " + CheckUtil.TranslateSid(sid) + " can create records");
                        }
                    }
                    foreach (var n in CheckUtil.Enumerate(ctx.SubtreeSearcher(part,
                        "(&(objectClass=dnsNode)(name=\\2a))", "distinguishedName")))
                        CheckUtil.AddDetail(wildcard, CheckUtil.Dn(n));
                }
                catch (Exception ex) { ctx.Log?.Invoke("    [!] ADIDNS check on " + part + " skipped: " + ex.Message); }
            }
            if (adidns.Details.Count > 0) yield return adidns;
            if (wildcard.Details.Count > 0) yield return wildcard;
            if (dnsUpdate.Details.Count > 0) yield return dnsUpdate;

            // ---- authentication policy silos (tier-0 isolation) ----
            int siloCount = 0;
            bool siloOk = true;
            try
            {
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(
                    "CN=AuthN Policy Configuration,CN=Services," + ctx.ConfigurationNamingContext,
                    "(objectClass=msDS-AuthNPolicySilo)", "cn")))
                    siloCount++;
            }
            catch (Exception ex)
            {
                // container absent => no silos defined (still worth reporting)
                ctx.Log?.Invoke("    [!] auth-silo container not found (treated as 0): " + ex.Message);
            }
            if (siloOk && siloCount == 0)
                yield return new Finding("E-NoAuthSilo", Category.Anomalies, Severity.Low, 4,
                    "No Authentication Policy Silos defined")
                    .Why("Silos (with Protected Users) confine tier-0 admin logons to specific hosts and block credential theft/relay reuse.")
                    .Fix("Create an authentication policy silo for tier-0 accounts.")
                    .Detail("0 silos found in the forest configuration.");
        }
    }
}
