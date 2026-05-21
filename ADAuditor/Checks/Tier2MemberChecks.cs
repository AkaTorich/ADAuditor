using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ServiceProcess;
using System.Threading.Tasks;
using Microsoft.Win32;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Tier 2 extended to member servers: the same registry/service posture as DCs,
    // probed in parallel. Read-only, current Windows session credentials.
    public sealed class Tier2MemberChecks : ICheck
    {
        public string Name => "Member Server Hardening (RPC)";

        private const int MaxHosts = 400;       // safety cap on very large estates
        private const int Parallelism = 16;

        private sealed class HostResult
        {
            public string Host;
            public bool Reachable;
            public bool SmbSigningWeak;
            public bool Smb1;
            public bool WDigest;
            public bool NoPpl;
            public bool Spooler;
            public string OsBuild;
        }

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            // enabled, non-DC computers advertising a Server OS
            var hosts = new List<string>();
            string filter = "(&(objectCategory=computer)(operatingSystem=*Server*)(!" +
                LdapBit.HasFlag("userAccountControl", (long)Uac.AccountDisabled) + ")(!" +
                LdapBit.HasFlag("userAccountControl", (long)Uac.ServerTrustAccount) + "))";
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(ctx.DefaultNamingContext, filter, "dNSHostName")))
            {
                string h = AuditContext.Str(r, "dNSHostName");
                if (!string.IsNullOrEmpty(h)) hosts.Add(h);
            }
            if (hosts.Count == 0) yield break;
            if (hosts.Count > MaxHosts)
            {
                ctx.Log?.Invoke("    [!] " + hosts.Count + " member servers; probing first " + MaxHosts + ".");
                hosts = hosts.GetRange(0, MaxHosts);
            }
            ctx.Log?.Invoke("    [*] probing " + hosts.Count + " member servers (parallel) ...");

            var results = new ConcurrentBag<HostResult>();
            Parallel.ForEach(hosts, new ParallelOptions { MaxDegreeOfParallelism = Parallelism },
                host => results.Add(Probe(host)));

            int reached = 0;
            var smbSigning = F("T2M-SmbSigning", Severity.High, 12, "Member servers without required SMB signing",
                "Servers that don't require SMB signing are NTLM-relay targets for lateral movement.",
                "Require SMB signing via GPO across all servers.");
            var smbv1 = F("T2M-Smbv1", Severity.Medium, 8, "Member servers with SMBv1 not disabled",
                "SMBv1 is obsolete and vulnerable; remove it everywhere.", "Disable/remove the SMB1 feature fleet-wide.");
            var wdigest = F("T2M-WDigest", Severity.High, 12, "Member servers caching cleartext credentials (WDigest)",
                "UseLogonCredential=1 keeps cleartext passwords in LSASS, dumped on compromise.", "Set WDigest UseLogonCredential=0.");
            var ppl = F("T2M-LsaProtection", Severity.Low, 4, "Member servers without LSA protection (RunAsPPL)",
                "Without RunAsPPL, LSASS secrets are easier to dump after a foothold.", "Enable RunAsPPL via GPO.");
            var spooler = F("T2M-Spooler", Severity.Medium, 8, "Print Spooler running on member servers",
                "Running spoolers broaden the coercion/relay surface across the estate.", "Disable the spooler where printing is not needed.");
            var osBuild = F("T2M-OsBuild", Severity.Info, 0, "Member server OS build inventory",
                "Build/patch inventory for member servers.", "Keep servers patched and supported.");

            foreach (var hr in results)
            {
                if (!hr.Reachable) continue;
                reached++;
                if (hr.SmbSigningWeak) CheckUtil.AddDetail(smbSigning, hr.Host);
                if (hr.Smb1) CheckUtil.AddDetail(smbv1, hr.Host);
                if (hr.WDigest) CheckUtil.AddDetail(wdigest, hr.Host);
                if (hr.NoPpl) CheckUtil.AddDetail(ppl, hr.Host);
                if (hr.Spooler) CheckUtil.AddDetail(spooler, hr.Host);
                if (!string.IsNullOrEmpty(hr.OsBuild)) CheckUtil.AddDetail(osBuild, hr.Host + " : " + hr.OsBuild);
            }
            ctx.Log?.Invoke("    [+] " + reached + "/" + hosts.Count + " member servers reachable via remote registry.");

            if (smbSigning.Details.Count > 0) yield return smbSigning;
            if (smbv1.Details.Count > 0) yield return smbv1;
            if (wdigest.Details.Count > 0) yield return wdigest;
            if (ppl.Details.Count > 0) yield return ppl;
            if (spooler.Details.Count > 0) yield return spooler;
            if (osBuild.Details.Count > 0) yield return osBuild;
        }

        private static HostResult Probe(string host)
        {
            var res = new HostResult { Host = host };
            try
            {
                using (var hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host, RegistryView.Registry64))
                {
                    res.Reachable = true;
                    res.SmbSigningWeak = RegInt(hklm, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature") != 1;
                    res.Smb1 = RegInt(hklm, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") != 0;
                    res.WDigest = RegInt(hklm, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential") == 1;
                    var p = RegInt(hklm, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL");
                    res.NoPpl = p == null || p == 0;
                    string build = RegStr(hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber");
                    int? ubr = RegInt(hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");
                    string pn = RegStr(hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
                    res.OsBuild = pn + " build " + build + (ubr != null ? "." + ubr : "");
                }
            }
            catch { res.Reachable = false; }

            try
            {
                using (var sc = new ServiceController("Spooler", host))
                    res.Spooler = sc.Status == ServiceControllerStatus.Running ||
                                  sc.Status == ServiceControllerStatus.StartPending;
            }
            catch { }
            return res;
        }

        private static Finding F(string id, Severity sev, int pts, string title, string why, string fix)
            => new Finding(id, Category.Anomalies, sev, pts, title).Why(why).Fix(fix);

        private static int? RegInt(RegistryKey root, string subkey, string name)
        {
            try
            {
                using (var k = root.OpenSubKey(subkey))
                {
                    var v = k?.GetValue(name);
                    if (v == null) return null;
                    if (v is int i) return i;
                    return int.TryParse(v.ToString(), out var p) ? (int?)p : null;
                }
            }
            catch { return null; }
        }

        private static string RegStr(RegistryKey root, string subkey, string name)
        {
            try { using (var k = root.OpenSubKey(subkey)) return k?.GetValue(name)?.ToString(); }
            catch { return null; }
        }
    }
}
