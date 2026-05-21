using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // AD CS (PKI) misconfigurations - notably the ESC1 template pattern.
    public sealed class CertChecks : ICheck
    {
        public string Name => "AD CS / PKI";

        private const int EnrolleeSuppliesSubject = 0x1;   // msPKI-Certificate-Name-Flag
        private const int PendAllRequests = 0x2;            // msPKI-Enrollment-Flag (manager approval)
        private const int NoSecurityExtension = 0x80000;    // msPKI-Enrollment-Flag (ESC9)
        private const string EkuEnrollmentAgent = "1.3.6.1.4.1.311.20.2.1"; // Certificate Request Agent
        private static readonly Guid Enroll = new Guid("0e10c968-78fb-11d2-90d4-00c04f79dc55");
        private static readonly Guid AutoEnroll = new Guid("a05b8cc2-17bc-4802-a710-e7c15ab866a2");

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string pkiBase = "CN=Public Key Services,CN=Services," + ctx.ConfigurationNamingContext;
            string domSid = ctx.DomainSid?.Value ?? "";
            var defaults = CheckUtil.DefaultPrivSids(domSid);

            // Enrollment Services = configured CAs
            var caInv = new Finding("C-CAs", Category.Anomalies, Severity.Info, 0,
                "Certificate Authorities (Enrollment Services)")
                .Why("AD CS expands the attack surface; ESC1-ESC8 abuse certificates to impersonate any account.")
                .Fix("Harden CA, audit template permissions, enable strong certificate mapping.");
            bool hasCa = false;
            try
            {
                foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(
                    "CN=Enrollment Services," + pkiBase, "(objectClass=pKIEnrollmentService)",
                    "cn", "dNSHostName")))
                {
                    hasCa = true;
                    CheckUtil.AddDetail(caInv, AuditContext.Str(r, "cn") + " @ " + AuditContext.Str(r, "dNSHostName"));
                }
            }
            catch { }
            if (!hasCa) yield break; // no PKI deployed
            yield return caInv;

            // ESC1: enrollee-supplied subject + auth EKU + no approval + no RA signature
            var esc1 = new Finding("C-ESC1", Category.Anomalies, Severity.Critical, 25,
                "Certificate templates vulnerable to ESC1")
                .Why("A template that lets the requester supply the subject AND issues a client-auth certificate without manager approval lets any enrollee request a cert as a domain admin.")
                .Fix("Disable ENROLLEE_SUPPLIES_SUBJECT, require manager approval, or restrict enrollment rights.");

            var noApproval = new Finding("C-Esc2AnyPurpose", Category.Anomalies, Severity.High, 15,
                "Templates with Any-Purpose / no EKU and enrollee-supplied subject (ESC2)")
                .Why("An Any-Purpose or SubCA certificate can be used for client authentication and more.")
                .Fix("Constrain EKUs and the subject name source.");

            var esc3 = new Finding("C-ESC3", Category.Anomalies, Severity.High, 15,
                "Enrollment Agent templates without manager approval (ESC3)")
                .Why("A Certificate Request Agent template lets the holder enroll on behalf of any user, then authenticate as them.")
                .Fix("Require manager approval / restrict enrollment on enrollment-agent templates.");

            var esc9 = new Finding("C-ESC9", Category.Anomalies, Severity.Medium, 10,
                "Templates with no security extension (ESC9)")
                .Why("CT_FLAG_NO_SECURITY_EXTENSION omits the SID binding, enabling certificate-mapping abuse when combined with altSecurityIdentities control.")
                .Fix("Remove the no-security-extension flag and enforce strong certificate mapping.");

            var esc15 = new Finding("C-ESC15", Category.Anomalies, Severity.High, 15,
                "Schema v1 templates allow application-policy injection (ESC15 / EKUwu)")
                .Why("On a v1 template with enrollee-supplied subject, a requester can inject arbitrary application policies (e.g. client auth) - CVE-2024-49019.")
                .Fix("Patch CA, raise template schema version, or disable enrollee-supplied subject.");

            foreach (var r in CheckUtil.Enumerate(CheckUtil.WithDacl(ctx.SubtreeSearcher(
                "CN=Certificate Templates," + pkiBase, "(objectClass=pKICertificateTemplate)",
                "cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
                "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy", "msPKI-Template-Schema-Version",
                "nTSecurityDescriptor"))))
            {
                string cn = AuditContext.Str(r, "cn");
                int nameFlag = (int)AuditContext.Int64Of(r, "msPKI-Certificate-Name-Flag");
                int enrollFlag = (int)AuditContext.Int64Of(r, "msPKI-Enrollment-Flag");
                int raSig = (int)AuditContext.Int64Of(r, "msPKI-RA-Signature");
                int schemaVer = (int)AuditContext.Int64Of(r, "msPKI-Template-Schema-Version");

                bool suppliesSubject = (nameFlag & EnrolleeSuppliesSubject) != 0;
                bool managerApproval = (enrollFlag & PendAllRequests) != 0;
                bool needsRaSig = raSig > 0;

                // Only exploitable if a non-privileged principal can actually enroll.
                bool lowPrivEnroll = LowPrivCanEnroll(CheckUtil.Bytes(r, "nTSecurityDescriptor"), defaults);
                if (!lowPrivEnroll) continue;

                var ekus = new List<string>();
                if (r.Properties.Contains("pKIExtendedKeyUsage"))
                    foreach (var v in r.Properties["pKIExtendedKeyUsage"]) ekus.Add(v.ToString());
                if (r.Properties.Contains("msPKI-Certificate-Application-Policy"))
                    foreach (var v in r.Properties["msPKI-Certificate-Application-Policy"]) ekus.Add(v.ToString());

                // ESC9: missing security extension (independent of subject source)
                if ((enrollFlag & NoSecurityExtension) != 0)
                    CheckUtil.AddDetail(esc9, cn);

                // ESC3: enrollment agent EKU without approval
                if (ekus.Contains(EkuEnrollmentAgent) && !managerApproval && !needsRaSig)
                    CheckUtil.AddDetail(esc3, cn);

                // ESC15: v1 schema template with enrollee-supplied subject
                if (schemaVer <= 1 && suppliesSubject && !managerApproval)
                    CheckUtil.AddDetail(esc15, cn + " (schema v" + schemaVer + ")");

                // ESC1 / ESC2 require enrollee-supplied subject, no approval, no RA signature
                if (!suppliesSubject || managerApproval || needsRaSig) continue;

                bool clientAuth = ekus.Count == 0 ||
                    ekus.Contains("1.3.6.1.5.5.7.3.2") ||   // Client Authentication
                    ekus.Contains("1.3.6.1.5.2.3.4") ||     // PKINIT Client Authentication
                    ekus.Contains("1.3.6.1.4.1.311.20.2.2");// Smart Card Logon
                bool anyPurpose = ekus.Count == 0 || ekus.Contains("2.5.29.37.0");

                if (clientAuth)
                {
                    CheckUtil.AddDetail(esc1, cn + " (enrollee-supplied subject + client-auth, no approval)");
                    // graph vector: any low-priv user can request a cert as a DA -> domain
                    if (!string.IsNullOrEmpty(domSid))
                        ctx.VectorEdges.Add(new GraphEdge { From = "S-1-5-11", To = domSid, Type = "ADCS-ESC1" });
                }
                else if (anyPurpose)
                    CheckUtil.AddDetail(noApproval, cn + " (Any-Purpose, no approval)");
            }

            if (esc1.Details.Count > 0) yield return esc1;
            if (noApproval.Details.Count > 0) yield return noApproval;
            if (esc3.Details.Count > 0) yield return esc3;
            if (esc9.Details.Count > 0) yield return esc9;
            if (esc15.Details.Count > 0) yield return esc15;

            // ---- ESC4: who can rewrite a certificate template ----
            var esc4 = new Finding("C-ESC4", Category.Anomalies, Severity.High, 15,
                "Certificate templates writable by non-admins (ESC4)")
                .Why("Write access to a template lets an attacker turn any template into an ESC1 and request a domain-admin certificate.")
                .Fix("Restrict template write/full-control to PKI administrators.");
            ScanPkiDacl(ctx, defaults, "CN=Certificate Templates," + pkiBase,
                "(objectClass=pKICertificateTemplate)", "cn", esc4);
            if (esc4.Details.Count > 0) yield return esc4;

            // ---- ESC5: control over CA objects and the PKI container ----
            var esc5 = new Finding("C-ESC5", Category.Anomalies, Severity.High, 15,
                "PKI objects (CA / containers) controllable by non-admins (ESC5)")
                .Why("Control over the CA object, NTAuthCertificates or the PKI container can compromise the entire PKI trust chain.")
                .Fix("Lock down ACLs on Public Key Services objects to tier-0 admins.");
            ScanPkiDacl(ctx, defaults, "CN=Enrollment Services," + pkiBase,
                "(objectClass=pKIEnrollmentService)", "cn", esc5);
            ScanPkiDacl(ctx, defaults, pkiBase, "(cn=NTAuthCertificates)", "cn", esc5);
            if (esc5.Details.Count > 0) yield return esc5;

            // ---- ESC13: issuance policy linked to a group ----
            var esc13 = new Finding("C-ESC13", Category.Anomalies, Severity.High, 15,
                "Issuance policy OIDs linked to groups (ESC13)")
                .Why("A certificate carrying this issuance policy grants membership in the linked group, escalating privileges on use.")
                .Fix("Review msDS-OIDToGroupLink mappings; remove links to privileged groups.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher("CN=OID," + pkiBase,
                "(msDS-OIDToGroupLink=*)", "cn", "displayName", "msDS-OIDToGroupLink")))
                CheckUtil.AddDetail(esc13, AuditContext.Str(r, "displayName") + " -> " +
                    AuditContext.Str(r, "msDS-OIDToGroupLink"));
            if (esc13.Details.Count > 0) yield return esc13;
        }

        // True if a non-default principal can enroll (Enroll/AutoEnroll extended right
        // or full control) - i.e. the template is actually requestable by low-priv users.
        private static bool LowPrivCanEnroll(byte[] sdb, HashSet<string> defaults)
        {
            if (sdb == null) return false;
            ActiveDirectorySecurity sd;
            try { sd = CheckUtil.ParseSd(sdb); } catch { return false; }
            foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                if (defaults.Contains(rule.IdentityReference.Value)) continue;
                var rights = rule.ActiveDirectoryRights;
                if (CheckUtil.FullControl(rights)) return true;
                if ((rights & ActiveDirectoryRights.ExtendedRight) != 0 &&
                    (rule.ObjectType == Guid.Empty || rule.ObjectType == Enroll || rule.ObjectType == AutoEnroll))
                    return true;
            }
            return false;
        }

        // Flag non-default principals with object-control rights over PKI objects.
        private static void ScanPkiDacl(AuditContext ctx, System.Collections.Generic.HashSet<string> defaults,
            string baseDn, string filter, string nameAttr, Finding f)
        {
            DirectorySearcher s;
            try { s = CheckUtil.WithDacl(ctx.SubtreeSearcher(baseDn, filter, nameAttr, "nTSecurityDescriptor")); }
            catch { return; }
            foreach (var r in CheckUtil.Enumerate(s))
            {
                byte[] sdb = CheckUtil.Bytes(r, "nTSecurityDescriptor");
                if (sdb == null) continue;
                System.DirectoryServices.ActiveDirectorySecurity sd;
                try { sd = CheckUtil.ParseSd(sdb); } catch { continue; }
                string name = AuditContext.Str(r, nameAttr);
                foreach (System.DirectoryServices.ActiveDirectoryAccessRule rule in
                         sd.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
                {
                    if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                    string sid = rule.IdentityReference.Value;
                    if (defaults.Contains(sid)) continue;
                    var rights = rule.ActiveDirectoryRights;
                    if (CheckUtil.FullControl(rights) ||
                        (rights & System.DirectoryServices.ActiveDirectoryRights.WriteDacl) != 0 ||
                        (rights & System.DirectoryServices.ActiveDirectoryRights.WriteOwner) != 0 ||
                        (rights & System.DirectoryServices.ActiveDirectoryRights.WriteProperty) != 0)
                        CheckUtil.AddDetail(f, CheckUtil.TranslateSid(sid) + " -> " + name);
                }
            }
        }
    }
}
