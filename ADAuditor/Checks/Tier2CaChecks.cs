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
            var esc6 = F("C-ESC6", Severity.Critical, 22, "CA allows requester-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2 / ESC6)",
                "With this CA policy flag any requester can put an arbitrary SAN (e.g. a domain admin UPN) into a certificate from any template.",
                "Remove the EDITF_ATTRIBUTESUBJECTALTNAME2 flag and restart the CA.");
            var esc11 = F("C-ESC11", Severity.High, 15, "CA does not enforce encryption for enrollment RPC (ESC11)",
                "Without IF_ENFORCEENCRYPTICERTREQUEST the ICertPassage RPC accepts unencrypted requests and can be NTLM-relayed.",
                "Set IF_ENFORCEENCRYPTICERTREQUEST in the CA InterfaceFlags.");

            foreach (var ca in cas)
            {
                if (string.IsNullOrEmpty(ca.host)) continue;
                ctx.Log?.Invoke("    [*] probing CA " + ca.cn + " @ " + ca.host + " ...");

                // ---- registry on the CA host: ESC7 (roles), ESC6 (EditFlags), ESC11 (InterfaceFlags) ----
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
                                    if (caKey == null) continue;
                                    var blob = caKey.GetValue("Security") as byte[];
                                    if (blob != null) InspectCaSecurity(blob, defaults, caName, esc7);

                                    // ESC11: InterfaceFlags must contain IF_ENFORCEENCRYPTICERTREQUEST (0x200)
                                    var ifl = caKey.GetValue("InterfaceFlags");
                                    if (ifl is int ifv && (ifv & 0x200) == 0)
                                        CheckUtil.AddDetail(esc11, caName + " (InterfaceFlags=0x" + ifv.ToString("X") + ")");

                                    // ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000) in a policy module EditFlags
                                    using (var pm = caKey.OpenSubKey("PolicyModules"))
                                    {
                                        if (pm != null)
                                            foreach (var mod in pm.GetSubKeyNames())
                                                using (var mk = pm.OpenSubKey(mod))
                                                {
                                                    if (mk?.GetValue("EditFlags") is int ef && (ef & 0x40000) != 0)
                                                        CheckUtil.AddDetail(esc6, caName + " (EditFlags=0x" + ef.ToString("X") + ")");
                                                }
                                    }
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

            if (esc6.Details.Count > 0) yield return esc6;
            if (esc7.Details.Count > 0) yield return esc7;
            if (esc8.Details.Count > 0) yield return esc8;
            if (esc11.Details.Count > 0) yield return esc11;
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
