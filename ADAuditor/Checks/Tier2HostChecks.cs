using System;
using System.Collections.Generic;
using System.ServiceProcess;
using Microsoft.Win32;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Tier 2: data that does NOT live in the directory - read from each DC's
    // registry over RPC (Remote Registry service) plus a service-status query.
    // Everything here is read-only. Uses the current Windows session credentials.
    public sealed class Tier2HostChecks : ICheck
    {
        public string Name => "Host Hardening (RPC)";

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            var dcs = CheckUtil.DomainControllers(ctx);
            if (dcs.Count == 0) yield break;

            var smbSigning = F("T2-SmbSigning", Severity.High, 12, "SMB signing not required on DC",
                "Without required SMB signing, captured authentication can be relayed (NTLM relay) to the DC.",
                "Set RequireSecuritySignature=1 (Microsoft network server: Digitally sign communications - always).");
            var smbv1 = F("T2-Smbv1", Severity.Medium, 8, "SMBv1 not disabled on DC",
                "SMBv1 is obsolete and vulnerable (EternalBlue family); it should be removed entirely.",
                "Disable/remove the SMB1 feature.");
            var ntlmLevel = F("T2-NtlmLevel", Severity.Medium, 8, "Weak LM/NTLM compatibility level",
                "A low LmCompatibilityLevel permits LM/NTLMv1, which are cheaply crackable and relayable.",
                "Set LmCompatibilityLevel to 5 (refuse LM & NTLMv1).");
            var wdigest = F("T2-WDigest", Severity.High, 12, "WDigest caches cleartext credentials",
                "UseLogonCredential=1 makes LSASS keep cleartext passwords, trivially dumped by Mimikatz.",
                "Set WDigest UseLogonCredential=0 (or remove it).");
            var lsaPpl = F("T2-LsaProtection", Severity.Medium, 8, "LSA protection (RunAsPPL) not enabled",
                "Without LSA protection, LSASS memory (and its secrets) is easier to dump.",
                "Enable RunAsPPL on domain controllers.");
            var ldapSign = F("T2-LdapSigning", Severity.High, 12, "LDAP signing not required",
                "Unsigned LDAP allows man-in-the-middle and NTLM relay to LDAP.",
                "Set NTDS LDAPServerIntegrity=2 (require signing).");
            var ldapCbt = F("T2-LdapChannelBinding", Severity.High, 12, "LDAP channel binding not enforced",
                "Without channel binding, LDAPS is relayable (e.g. to AD CS / ESC8).",
                "Set LdapEnforceChannelBinding=2 (always).");
            var esc10Kdc = F("T2-Esc10Kdc", Severity.High, 12, "Weak KDC certificate binding (ESC10)",
                "StrongCertificateBindingEnforcement below 2 lets a certificate without strong SID binding authenticate as another user.",
                "Set Kdc StrongCertificateBindingEnforcement=2.");
            var esc10Sch = F("T2-Esc10Schannel", Severity.High, 12, "Weak Schannel certificate mapping (ESC10)",
                "CertificateMappingMethods including UPN (0x4) enables weak/forgeable certificate mapping.",
                "Remove the 0x4 (UPN) bit from Schannel CertificateMappingMethods.");
            var noLmHash = F("T2-NoLMHash", Severity.Medium, 8, "LM hashes not blocked from storage",
                "Without NoLMHash, account LM hashes are stored - trivially crackable to the cleartext password.",
                "Set NoLMHash=1 (Network security: Do not store LAN Manager hash value).");
            var spooler = F("T2-Spooler", Severity.High, 12, "Print Spooler running on DC",
                "A running spooler exposes the Printer Bug / PetitPotam coercion used to relay DC authentication (e.g. to ADCS or for unconstrained-delegation theft).",
                "Stop and disable the Print Spooler service on domain controllers.");
            var osBuild = F("T2-OsBuild", Severity.Info, 0, "Domain controller OS build",
                "Build/patch level inventory; compare against current monthly updates to spot unpatched DCs.",
                "Keep DCs on a supported, fully patched build.");

            foreach (var host in dcs)
            {
                ctx.Log?.Invoke("    [*] probing " + host + " ...");
                RegistryKey hklm = null;
                try { hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host, RegistryView.Registry64); }
                catch (Exception ex) { ctx.Log?.Invoke("    [!] registry on " + host + " unreachable: " + ex.Message); }

                if (hklm != null)
                {
                    using (hklm)
                    {
                        int? v;

                        v = RegInt(hklm, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature");
                        if (v != 1) CheckUtil.AddDetail(smbSigning, host);

                        v = RegInt(hklm, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
                        if (v != 0) CheckUtil.AddDetail(smbv1, host + " (SMB1=" + (v?.ToString() ?? "unset") + ")");

                        v = RegInt(hklm, @"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel");
                        if (v != null && v < 3) CheckUtil.AddDetail(ntlmLevel, host + " (LmCompatibilityLevel=" + v + ")");

                        v = RegInt(hklm, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential");
                        if (v == 1) CheckUtil.AddDetail(wdigest, host);

                        v = RegInt(hklm, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL");
                        if (v == null || v == 0) CheckUtil.AddDetail(lsaPpl, host);

                        v = RegInt(hklm, @"SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash");
                        if (v == null || v == 0) CheckUtil.AddDetail(noLmHash, host);

                        v = RegInt(hklm, @"SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity");
                        if (v != 2) CheckUtil.AddDetail(ldapSign, host + " (LDAPServerIntegrity=" + (v?.ToString() ?? "unset") + ")");

                        v = RegInt(hklm, @"SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "LdapEnforceChannelBinding");
                        if (v == null || v < 2) CheckUtil.AddDetail(ldapCbt, host + " (LdapEnforceChannelBinding=" + (v?.ToString() ?? "unset") + ")");

                        v = RegInt(hklm, @"SYSTEM\CurrentControlSet\Services\Kdc", "StrongCertificateBindingEnforcement");
                        if (v != null && v < 2) CheckUtil.AddDetail(esc10Kdc, host + " (StrongCertificateBindingEnforcement=" + v + ")");

                        v = RegInt(hklm, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "CertificateMappingMethods");
                        if (v != null && (v.Value & 0x4) != 0) CheckUtil.AddDetail(esc10Sch, host + " (CertificateMappingMethods=0x" + v.Value.ToString("X") + ")");

                        string build = RegStr(hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber");
                        int? ubr = RegInt(hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");
                        string pn = RegStr(hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
                        CheckUtil.AddDetail(osBuild, host + " : " + pn + " build " + build + (ubr != null ? "." + ubr : ""));
                    }
                }

                // Print Spooler service status (SCM over RPC; read-only).
                try
                {
                    using (var sc = new ServiceController("Spooler", host))
                    {
                        if (sc.Status == ServiceControllerStatus.Running ||
                            sc.Status == ServiceControllerStatus.StartPending)
                            CheckUtil.AddDetail(spooler, host);
                    }
                }
                catch (Exception ex) { ctx.Log?.Invoke("    [!] spooler query on " + host + " failed: " + ex.Message); }
            }

            if (smbSigning.Details.Count > 0) yield return smbSigning;
            if (smbv1.Details.Count > 0) yield return smbv1;
            if (ntlmLevel.Details.Count > 0) yield return ntlmLevel;
            if (wdigest.Details.Count > 0) yield return wdigest;
            if (lsaPpl.Details.Count > 0) yield return lsaPpl;
            if (noLmHash.Details.Count > 0) yield return noLmHash;
            if (ldapSign.Details.Count > 0) yield return ldapSign;
            if (ldapCbt.Details.Count > 0) yield return ldapCbt;
            if (esc10Kdc.Details.Count > 0) yield return esc10Kdc;
            if (esc10Sch.Details.Count > 0) yield return esc10Sch;
            if (spooler.Details.Count > 0) yield return spooler;
            if (osBuild.Details.Count > 0) yield return osBuild;
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
            try
            {
                using (var k = root.OpenSubKey(subkey))
                    return k?.GetValue(name)?.ToString();
            }
            catch { return null; }
        }
    }
}
