using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // BloodHound-style ACL indicators (without graph): who - other than admins -
    // has control over accounts, groups, OUs, GPO links, LAPS and gMSA secrets.
    public sealed class AdvancedAclChecks : ICheck
    {
        public string Name => "ACL Indicators";

        private static readonly Guid ForceChangePwd = new Guid("00299570-246d-11d0-a768-00aa006e0529");
        private static readonly Guid MemberAttr = new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2");
        private static readonly Guid GpLink = new Guid("f30e3bbe-9ff0-11d1-b603-0000f80367c1");

        private const ActiveDirectoryRights Full = ActiveDirectoryRights.GenericAll;
        private const ActiveDirectoryRights WriteDacl = ActiveDirectoryRights.WriteDacl;
        private const ActiveDirectoryRights WriteOwner = ActiveDirectoryRights.WriteOwner;
        private const ActiveDirectoryRights WriteProp = ActiveDirectoryRights.WriteProperty;
        private const ActiveDirectoryRights ExtRight = ActiveDirectoryRights.ExtendedRight;
        private const ActiveDirectoryRights Self = ActiveDirectoryRights.Self;

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string baseDn = ctx.DefaultNamingContext;
            string domSid = ctx.DomainSid?.Value ?? "";
            var defaults = CheckUtil.DefaultPrivSids(domSid);

            Guid? keyCred = CheckUtil.SchemaGuid(ctx, "msDS-KeyCredentialLink");
            Guid? laps = CheckUtil.SchemaGuid(ctx, "ms-Mcs-AdmPwd") ?? CheckUtil.SchemaGuid(ctx, "msLAPS-Password");

            var genericAll = Mk("X-AclGenericAll", Severity.High, 14, "Non-admins with Full Control (GenericAll) over accounts/groups",
                "GenericAll lets the principal reset passwords, add members, or take over the object completely.",
                "Remove the ACE or restrict it to tier-0 admins.");
            var writeDaclOwner = Mk("X-AclWriteDaclOwner", Severity.High, 14, "Non-admins can rewrite DACL / take ownership",
                "WriteDacl or WriteOwner is equivalent to full control - the principal can grant itself anything.",
                "Remove WriteDacl/WriteOwner from non-admin principals.");
            var forceChange = Mk("X-AclForceChangePwd", Severity.High, 12, "Non-admins can force-reset account passwords",
                "The User-Force-Change-Password right lets the principal set a new password without knowing the old one.",
                "Remove this extended right from non-admins.");
            var writeMember = Mk("X-AclWriteMember", Severity.High, 12, "Non-admins can modify group membership",
                "Write access to the member attribute lets the principal add itself to the group (e.g. a privileged group).",
                "Remove write-member rights from non-admins.");
            var shadowWrite = Mk("X-ShadowCredWrite", Severity.High, 14, "Non-admins can write msDS-KeyCredentialLink (Shadow Credentials)",
                "Writing key credentials lets the principal authenticate as the target via PKINIT (Whisker/ESC abuse).",
                "Restrict write access to msDS-KeyCredentialLink to Key Admins only.");
            var allExt = Mk("X-AclAllExtended", Severity.High, 12, "Non-admins hold All Extended Rights over objects",
                "AllExtendedRights includes password reset, DCSync (on the domain), and more.",
                "Scope extended rights tightly.");
            var lapsRead = Mk("X-LapsReaders", Severity.Medium, 8, "Non-admins can read LAPS passwords",
                "Read access to the confidential LAPS attribute exposes local administrator passwords for lateral movement.",
                "Limit LAPS read rights to dedicated admin groups.");

            // ---- single SD scan over users, computers and groups ----
            var s = CheckUtil.WithDacl(ctx.SubtreeSearcher(baseDn,
                "(|(objectClass=user)(objectClass=group))",
                "sAMAccountName", "objectClass", "nTSecurityDescriptor"));
            foreach (var r in CheckUtil.Enumerate(s))
            {
                byte[] sdb = CheckUtil.Bytes(r, "nTSecurityDescriptor");
                if (sdb == null) continue;
                ActiveDirectorySecurity sd;
                try { sd = CheckUtil.ParseSd(sdb); } catch { continue; }

                string name = CheckUtil.Sam(r);
                bool isGroup = CheckUtil.HasClass(r, "group");

                foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                    string sid = rule.IdentityReference.Value;
                    if (defaults.Contains(sid)) continue;

                    var rights = rule.ActiveDirectoryRights;
                    var ot = rule.ObjectType;

                    if ((rights & Full) == Full)
                        CheckUtil.AddDetail(genericAll, Who(sid) + " -> " + name);
                    if ((rights & WriteDacl) != 0 || (rights & WriteOwner) != 0)
                        CheckUtil.AddDetail(writeDaclOwner, Who(sid) + " -> " + name);

                    if ((rights & ExtRight) != 0)
                    {
                        if (ot == Guid.Empty) CheckUtil.AddDetail(allExt, Who(sid) + " -> " + name);
                        else if (ot == ForceChangePwd) CheckUtil.AddDetail(forceChange, Who(sid) + " -> " + name);
                        else if (laps != null && ot == laps.Value) CheckUtil.AddDetail(lapsRead, Who(sid) + " -> " + name);
                    }

                    if (((rights & WriteProp) != 0 || (rights & Self) != 0) && isGroup &&
                        (ot == MemberAttr || ot == Guid.Empty))
                        CheckUtil.AddDetail(writeMember, Who(sid) + " -> " + name);

                    if ((rights & WriteProp) != 0 && keyCred != null && ot == keyCred.Value)
                        CheckUtil.AddDetail(shadowWrite, Who(sid) + " -> " + name);

                    // GenericAll implicitly grants LAPS read too
                    if (laps != null && (rights & Full) == Full && CheckUtil.HasClass(r, "computer"))
                        CheckUtil.AddDetail(lapsRead, Who(sid) + " -> " + name + " (via GenericAll)");
                }
            }

            if (genericAll.Details.Count > 0) yield return genericAll;
            if (writeDaclOwner.Details.Count > 0) yield return writeDaclOwner;
            if (forceChange.Details.Count > 0) yield return forceChange;
            if (writeMember.Details.Count > 0) yield return writeMember;
            if (shadowWrite.Details.Count > 0) yield return shadowWrite;
            if (allExt.Details.Count > 0) yield return allExt;
            if (lapsRead.Details.Count > 0) yield return lapsRead;

            // ---- OU control and GPO-link write ----
            var ouControl = Mk("X-AclOuControl", Severity.High, 12, "Non-admins control Organizational Units",
                "Full control over an OU lets the principal push GPOs or move/own child objects.",
                "Remove non-admin control from OUs.");
            var gpLinkWrite = Mk("X-AclGpLinkWrite", Severity.High, 12, "Non-admins can link GPOs to OUs (write gPLink)",
                "Writing gPLink lets the principal apply an attacker-controlled GPO to everything under the OU.",
                "Restrict gPLink write to admins.");
            var ouScan = CheckUtil.WithDacl(ctx.SubtreeSearcher(baseDn,
                "(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
                "ou", "distinguishedName", "nTSecurityDescriptor"));
            foreach (var r in CheckUtil.Enumerate(ouScan))
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
                    if ((rights & Full) == Full || (rights & WriteDacl) != 0 || (rights & WriteOwner) != 0)
                        CheckUtil.AddDetail(ouControl, Who(sid) + " -> " + dn);
                    if ((rights & WriteProp) != 0 && (ot == GpLink || ot == Guid.Empty))
                        CheckUtil.AddDetail(gpLinkWrite, Who(sid) + " -> " + dn);
                }
            }
            if (ouControl.Details.Count > 0) yield return ouControl;
            if (gpLinkWrite.Details.Count > 0) yield return gpLinkWrite;

            // ---- gMSA password retrievers ----
            var gmsaRead = Mk("X-GmsaRetrievers", Severity.Medium, 8, "Non-admins can retrieve gMSA passwords",
                "msDS-GroupMSAMembership lists principals allowed to read the managed password - effectively run as that service account.",
                "Limit PrincipalsAllowedToRetrieveManagedPassword to required hosts only.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(objectClass=msDS-GroupManagedServiceAccount)",
                "sAMAccountName", "msDS-GroupMSAMembership")))
            {
                byte[] sdb = CheckUtil.Bytes(r, "msDS-GroupMSAMembership");
                if (sdb == null) continue;
                ActiveDirectorySecurity sd;
                try { sd = CheckUtil.ParseSd(sdb); } catch { continue; }
                string name = CheckUtil.Sam(r);
                foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                    string sid = rule.IdentityReference.Value;
                    if (defaults.Contains(sid)) continue;
                    CheckUtil.AddDetail(gmsaRead, Who(sid) + " -> " + name);
                }
            }
            if (gmsaRead.Details.Count > 0) yield return gmsaRead;
        }

        private static string Who(string sid) => CheckUtil.TranslateSid(sid) + " [" + sid + "]";

        private static Finding Mk(string id, Severity sev, int pts, string title, string why, string fix)
            => new Finding(id, Category.PrivilegedAccounts, sev, pts, title).Why(why).Fix(fix);
    }
}
