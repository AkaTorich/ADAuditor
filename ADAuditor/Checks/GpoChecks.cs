using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using System.Text;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Group Policy hygiene that is visible purely through LDAP.
    public sealed class GpoChecks : ICheck
    {
        public string Name => "Group Policy";

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string baseDn = ctx.DefaultNamingContext;
            string policiesDn = "CN=Policies,CN=System," + baseDn;
            string domSid = ctx.DomainSid?.Value ?? "";
            var defaults = CheckUtil.DefaultPrivSids(domSid);

            // Collect every gPLink reference across the domain and the sites container.
            var linked = new StringBuilder();
            foreach (var scopeDn in new[] { baseDn, "CN=Sites," + ctx.ConfigurationNamingContext })
            {
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(scopeDn, "(gPLink=*)", "gPLink")))
                    linked.Append(AuditContext.Str(r, "gPLink").ToLowerInvariant()).Append('|');
            }
            string linkedText = linked.ToString();

            var unlinked = new Finding("G-UnlinkedGpo", Category.Anomalies, Severity.Low, 3,
                "GPOs that are not linked anywhere")
                .Why("Unlinked GPOs do nothing but accumulate; they hide stale settings and complicate review.")
                .Fix("Remove or relink orphaned GPOs.");

            var writable = new Finding("G-GpoWritable", Category.Anomalies, Severity.High, 14,
                "GPOs writable by non-admins")
                .Why("Write access to a GPO lets the principal push code/settings (logon scripts, scheduled tasks, restricted groups) to every linked computer or user.")
                .Fix("Restrict GPO edit rights to tier-0 administrators.");

            var scan = CheckUtil.WithDacl(ctx.SubtreeSearcher(policiesDn,
                "(objectClass=groupPolicyContainer)",
                "cn", "displayName", "distinguishedName", "nTSecurityDescriptor"));
            foreach (var r in CheckUtil.Enumerate(scan))
            {
                string cn = AuditContext.Str(r, "cn");           // {GUID}
                string disp = AuditContext.Str(r, "displayName");
                string label = (string.IsNullOrEmpty(disp) ? cn : disp) + " " + cn;

                if (!string.IsNullOrEmpty(cn) && linkedText.IndexOf(cn.ToLowerInvariant(), StringComparison.Ordinal) < 0)
                    CheckUtil.AddDetail(unlinked, label);

                byte[] sdb = CheckUtil.Bytes(r, "nTSecurityDescriptor");
                if (sdb == null) continue;
                ActiveDirectorySecurity sd;
                try { sd = CheckUtil.ParseSd(sdb); } catch { continue; }
                foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                    string sid = rule.IdentityReference.Value;
                    if (defaults.Contains(sid)) continue;
                    var rights = rule.ActiveDirectoryRights;
                    bool canWrite =
                        CheckUtil.FullControl(rights) ||
                        (rights & ActiveDirectoryRights.WriteProperty) != 0 ||
                        (rights & ActiveDirectoryRights.WriteDacl) != 0 ||
                        (rights & ActiveDirectoryRights.WriteOwner) != 0;
                    if (canWrite)
                        CheckUtil.AddDetail(writable, CheckUtil.TranslateSid(sid) + " -> " + label);
                }
            }

            if (unlinked.Details.Count > 0) yield return unlinked;
            if (writable.Details.Count > 0) yield return writable;
        }
    }
}
