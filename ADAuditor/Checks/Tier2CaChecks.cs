using System;
using System.Collections.Generic;
using System.Net;
using System.Security.AccessControl;
using Microsoft.Win32;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Tier 2 for AD CS: CA role security (ESC7) read from the CA host registry,
    // and a read-only HTTP probe of web enrollment (ESC8). Read-only.
    public sealed class Tier2CaChecks : ICheck
    {
        public string Name => "AD CS Host (RPC/HTTP)";

        private const int ManageCa = 0x1;       // CA_ACCESS_ADMIN
        private const int ManageCertificates = 0x2; // CA_ACCESS_OFFICER

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string pkiBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services," + ctx.ConfigurationNamingContext;
            string domSid = ctx.DomainSid?.Value ?? "";
            var defaults = CheckUtil.DefaultPrivSids(domSid);

            var cas = new List<(string cn, string host)>();
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(pkiBase,
                "(objectClass=pKIEnrollmentService)", "cn", "dNSHostName")))
                cas.Add((AuditContext.Str(r, "cn"), AuditContext.Str(r, "dNSHostName")));
            if (cas.Count == 0) yield break;

            var esc7 = F("C-ESC7", Severity.High, 15, "Non-admins hold CA management roles (ESC7)",
                "Manage CA / Manage Certificates rights let a principal approve pending requests or enable dangerous policies - a path to forging certificates.",
                "Remove Manage CA / Manage Certificates from non-tier-0 principals.");
            var esc8 = F("C-ESC8", Severity.High, 15, "AD CS web enrollment exposed over HTTP/NTLM (ESC8)",
                "An HTTP enrollment endpoint accepting NTLM can be targeted by relay (coerce a DC, relay to certsrv, obtain a DC certificate).",
                "Disable HTTP web enrollment, enforce HTTPS with Extended Protection, or remove the role.");

            foreach (var ca in cas)
            {
                if (string.IsNullOrEmpty(ca.host)) continue;
                ctx.Log?.Invoke("    [*] probing CA " + ca.cn + " @ " + ca.host + " ...");

                // ---- ESC7: read CertSvc\Configuration\<CA>\Security from the CA host ----
                try
                {
                    using (var hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, ca.host, RegistryView.Registry64))
                    using (var cfg = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"))
                    {
                        if (cfg != null)
                        {
                            foreach (var caName in cfg.GetSubKeyNames())
                            {
                                using (var caKey = cfg.OpenSubKey(caName))
                                {
                                    var blob = caKey?.GetValue("Security") as byte[];
                                    if (blob == null) continue;
                                    InspectCaSecurity(blob, defaults, caName, esc7);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex) { ctx.Log?.Invoke("    [!] CA registry on " + ca.host + " unreachable: " + ex.Message); }

                // ---- ESC8: probe HTTP web enrollment ----
                if (ProbeHttpEnrollment(ca.host, out string detail))
                    CheckUtil.AddDetail(esc8, ca.host + " : " + detail);
            }

            if (esc7.Details.Count > 0) yield return esc7;
            if (esc8.Details.Count > 0) yield return esc8;
        }

        private static void InspectCaSecurity(byte[] blob, HashSet<string> defaults, string caName, Finding esc7)
        {
            RawSecurityDescriptor sd;
            try { sd = new RawSecurityDescriptor(blob, 0); }
            catch { return; }
            if (sd.DiscretionaryAcl == null) return;

            foreach (GenericAce ace in sd.DiscretionaryAcl)
            {
                if (!(ace is CommonAce ca)) continue;
                if (ca.AceType != AceType.AccessAllowed) continue;
                string sid = ca.SecurityIdentifier.Value;
                if (defaults.Contains(sid)) continue;
                var roles = new List<string>();
                if ((ca.AccessMask & ManageCa) != 0) roles.Add("ManageCA");
                if ((ca.AccessMask & ManageCertificates) != 0) roles.Add("ManageCertificates");
                if (roles.Count > 0)
                    CheckUtil.AddDetail(esc7, CheckUtil.TranslateSid(sid) + " : " + string.Join("+", roles) + " on " + caName);
            }
        }

        // Read-only GET; we only inspect status / WWW-Authenticate, never send credentials.
        private static bool ProbeHttpEnrollment(string host, out string detail)
        {
            detail = null;
            try
            {
                var req = (HttpWebRequest)WebRequest.Create("http://" + host + "/certsrv/");
                req.Method = "GET";
                req.Timeout = 5000;
                req.AllowAutoRedirect = false;
                req.UseDefaultCredentials = false;
                req.UserAgent = "ADAuditor";
                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    detail = "HTTP enrollment reachable (status " + (int)resp.StatusCode + ")";
                    return true;
                }
            }
            catch (WebException wex)
            {
                if (wex.Response is HttpWebResponse hr)
                {
                    string auth = hr.Headers["WWW-Authenticate"] ?? "";
                    if ((int)hr.StatusCode == 401 &&
                        (auth.IndexOf("NTLM", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         auth.IndexOf("Negotiate", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        detail = "HTTP enrollment requires NTLM/Negotiate (relay candidate)";
                        return true;
                    }
                }
                return false;
            }
            catch { return false; }
        }

        private static Finding F(string id, Severity sev, int pts, string title, string why, string fix)
            => new Finding(id, Category.Anomalies, sev, pts, title).Why(why).Fix(fix);
    }
}
