using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // dMSA / BadSuccessor (Windows Server 2025). A principal that can create a delegated
    // Managed Service Account (CreateChild on any OU) or fully control an OU can plant a
    // dMSA, link it to a privileged victim via msDS-ManagedAccountPrecededByLink and
    // inherit the victim's rights - a one-step path to domain compromise.
    public sealed class BadSuccessorChecks : ICheck
    {
        public string Name => "dMSA / BadSuccessor";

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string baseDn = ctx.DefaultNamingContext;
            string domSid = ctx.DomainSid?.Value ?? "";
            var defaults = CheckUtil.DefaultPrivSids(domSid);

            // dMSA class exists only on a Server 2025 schema; otherwise no attack surface.
            Guid? dmsaClass = ClassGuid(ctx, "msDS-DelegatedManagedServiceAccount");
            if (dmsaClass == null) yield break;

            var badsucc = new Finding("M-BadSuccessor", Category.PrivilegedAccounts, Severity.Critical, 25,
                "BadSuccessor: non-admins can create / control dMSA objects")
                .Why("With CreateChild for dMSA on an OU (or full control of the OU) an attacker creates a delegated MSA, links it to a privileged account and inherits its access - direct domain compromise.")
                .Fix("Remove CreateChild/full-control over OUs from non-tier-0 principals; restrict who can create msDS-DelegatedManagedServiceAccount objects.");

            // Only OUs / the domain root and the Managed Service Accounts container are
            // valid places to plant a dMSA - NOT arbitrary containers (e.g. CN=MicrosoftDNS,
            // where DnsAdmins legitimately holds CreateChild).
            try
            {
                Scan(CheckUtil.WithDacl(ctx.SubtreeSearcher(baseDn,
                    "(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
                    "distinguishedName", "nTSecurityDescriptor")), defaults, dmsaClass.Value, badsucc);
            }
            catch (Exception ex) { ctx.Log?.Invoke("    [!] BadSuccessor OU scan skipped: " + ex.Message); }

            try
            {
                Scan(CheckUtil.WithDacl(ctx.Searcher("CN=Managed Service Accounts," + baseDn,
                    "(objectClass=*)", SearchScope.Base, "distinguishedName", "nTSecurityDescriptor")),
                    defaults, dmsaClass.Value, badsucc);
            }
            catch { }

            if (badsucc.Details.Count > 0) yield return badsucc;

            // existing dMSA migration links (could be a planted BadSuccessor takeover)
            var linked = new Finding("M-DmsaPrecededBy", Category.PrivilegedAccounts, Severity.High, 12,
                "dMSA objects linked to a predecessor account")
                .Why("msDS-ManagedAccountPrecededByLink makes the dMSA inherit the linked account's privileges; an unexpected link is the BadSuccessor takeover artifact.")
                .Fix("Verify every dMSA migration link is legitimate; remove unexpected ones.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(objectClass=msDS-DelegatedManagedServiceAccount)",
                "sAMAccountName", "msDS-ManagedAccountPrecededByLink")))
            {
                string link = AuditContext.Str(r, "msDS-ManagedAccountPrecededByLink");
                if (!string.IsNullOrEmpty(link))
                    CheckUtil.AddDetail(linked, CheckUtil.Sam(r) + " <- " + link);
            }
            if (linked.Details.Count > 0) yield return linked;
        }

        private static void Scan(DirectorySearcher s, HashSet<string> defaults, Guid dmsaClass, Finding badsucc)
        {
            foreach (var r in CheckUtil.Enumerate(s))
            {
                byte[] sdb = CheckUtil.Bytes(r, "nTSecurityDescriptor");
                if (sdb == null) continue;
                ActiveDirectorySecurity sd;
                try { sd = CheckUtil.ParseSd(sdb); } catch { continue; }
                string dn = CheckUtil.Dn(r);

                foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                    string sid = rule.IdentityReference.Value;
                    if (defaults.Contains(sid)) continue;
                    var rights = rule.ActiveDirectoryRights;
                    var ot = rule.ObjectType;

                    bool canCreate = (rights & ActiveDirectoryRights.CreateChild) != 0 &&
                                     (ot == Guid.Empty || ot == dmsaClass);
                    bool ownsOu = CheckUtil.FullControl(rights) ||
                                  (rights & ActiveDirectoryRights.WriteDacl) != 0 ||
                                  (rights & ActiveDirectoryRights.WriteOwner) != 0;
                    if (canCreate || ownsOu)
                        CheckUtil.AddDetail(badsucc, CheckUtil.TranslateSid(sid) + " -> " + ShortDn(dn) +
                            (canCreate ? " (create dMSA)" : " (owns OU)"));
                }
            }
        }

        private static Guid? ClassGuid(AuditContext ctx, string ldapName)
        {
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(ctx.SchemaNamingContext,
                "(&(objectClass=classSchema)(lDAPDisplayName=" + ldapName + "))", "schemaIDGUID")))
            {
                var b = CheckUtil.Bytes(r, "schemaIDGUID");
                if (b != null && b.Length == 16) return new Guid(b);
            }
            return null;
        }

        private static string ShortDn(string dn)
        {
            int i = dn.IndexOf(',');
            return i > 0 ? dn.Substring(0, i) : dn;
        }
    }
}
