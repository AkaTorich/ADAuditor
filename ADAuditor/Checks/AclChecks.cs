using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Dangerous ACEs on crown-jewel objects: DCSync rights and AdminSDHolder tampering.
    public sealed class AclChecks : ICheck
    {
        public string Name => "ACL / DACL";

        private static readonly Guid GetChanges = new Guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
        private static readonly Guid GetChangesAll = new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string domSid = ctx.DomainSid?.Value ?? "";
            var defaults = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "S-1-5-18",        // LocalSystem
                "S-1-5-9",         // Enterprise Domain Controllers
                "S-1-5-32-544",    // BUILTIN\Administrators
                "S-1-5-32-548",    // Account Operators (default on some objects)
                domSid + "-512",   // Domain Admins
                domSid + "-516",   // Domain Controllers
                domSid + "-519",   // Enterprise Admins
                domSid + "-518",   // Schema Admins
                domSid + "-498",   // Enterprise Read-only DCs
                domSid + "-500"    // built-in admin
            };

            // ---- DCSync rights on the domain head ----
            var dcsync = new Finding("X-DCSync", Category.PrivilegedAccounts, Severity.Critical, 25,
                "Non-default principals can perform DCSync")
                .Why("DS-Replication-Get-Changes(-All) lets the principal pull every credential in the domain, including krbtgt - equivalent to full compromise.")
                .Fix("Remove replication rights from any principal that is not a Domain Controller.");

            try
            {
                using (var dom = ctx.Bind(ctx.DefaultNamingContext))
                {
                    dom.Options.SecurityMasks = SecurityMasks.Dacl;
                    var grants = new Dictionary<string, (bool getChanges, bool getAll, bool genericAll, string name)>();
                    foreach (ActiveDirectoryAccessRule rule in
                             dom.ObjectSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    {
                        if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                        string sid = rule.IdentityReference.Value;
                        if (defaults.Contains(sid)) continue;

                        bool genAll = CheckUtil.FullControl(rule.ActiveDirectoryRights);
                        bool ext = (rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) != 0;
                        bool gc = ext && rule.ObjectType == GetChanges;
                        bool ga = ext && rule.ObjectType == GetChangesAll;
                        bool extAll = ext && rule.ObjectType == Guid.Empty; // all extended rights

                        if (!genAll && !gc && !ga && !extAll) continue;

                        grants.TryGetValue(sid, out var cur);
                        grants[sid] = (cur.getChanges || gc || extAll,
                                       cur.getAll || ga || extAll,
                                       cur.genericAll || genAll,
                                       Translate(sid));
                    }

                    foreach (var kv in grants)
                    {
                        var g = kv.Value;
                        if (g.genericAll || (g.getChanges && g.getAll))
                            CheckUtil.AddDetail(dcsync, g.name + " [" + kv.Key + "]");
                    }
                }
            }
            catch (Exception ex)
            {
                ctx.Log?.Invoke("    [!] DCSync DACL read failed: " + ex.Message);
            }
            if (dcsync.Details.Count > 0) yield return dcsync;

            // ---- AdminSDHolder DACL tampering ----
            var sdholder = new Finding("X-AdminSDHolder", Category.PrivilegedAccounts, Severity.High, 18,
                "Non-default principals with full control over AdminSDHolder")
                .Why("AdminSDHolder's ACL is stamped onto every protected (adminCount=1) object hourly; a backdoor ACE here re-grants attacker access even after cleanup.")
                .Fix("Remove unexpected ACEs from CN=AdminSDHolder,CN=System.");
            try
            {
                using (var sdh = ctx.Bind("CN=AdminSDHolder,CN=System," + ctx.DefaultNamingContext))
                {
                    sdh.Options.SecurityMasks = SecurityMasks.Dacl;
                    foreach (ActiveDirectoryAccessRule rule in
                             sdh.ObjectSecurity.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                    {
                        if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                        string sid = rule.IdentityReference.Value;
                        if (defaults.Contains(sid)) continue;

                        var rights = rule.ActiveDirectoryRights;
                        bool dangerous =
                            CheckUtil.FullControl(rights) ||
                            (rights & ActiveDirectoryRights.WriteDacl) != 0 ||
                            (rights & ActiveDirectoryRights.WriteOwner) != 0;
                        if (dangerous)
                            CheckUtil.AddDetail(sdholder, Translate(sid) + " : " + rights);
                    }
                }
            }
            catch (Exception ex)
            {
                ctx.Log?.Invoke("    [!] AdminSDHolder DACL read failed: " + ex.Message);
            }
            if (sdholder.Details.Count > 0) yield return sdholder;
        }

        private static string Translate(string sid)
        {
            try
            {
                var acc = new SecurityIdentifier(sid).Translate(typeof(NTAccount));
                return acc.Value;
            }
            catch { return sid; }
        }
    }
}
