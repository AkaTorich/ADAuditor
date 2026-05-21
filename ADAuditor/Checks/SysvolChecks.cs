using System;
using System.Collections.Generic;
using System.IO;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Group Policy Preferences passwords left in SYSVOL (MS14-025 / cpassword).
    public sealed class SysvolChecks : ICheck
    {
        public string Name => "SYSVOL / GPP";

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string host = string.IsNullOrEmpty(ctx.DomainDns) ? ctx.Server : ctx.DomainDns;
            if (string.IsNullOrEmpty(host)) yield break;

            string policies = @"\\" + host + @"\SYSVOL\" + ctx.DomainDns + @"\Policies";

            var gpp = new Finding("V-GppPassword", Category.Anomalies, Severity.Critical, 25,
                "Group Policy Preferences password (cpassword) in SYSVOL")
                .Why("The AES key for cpassword is published by Microsoft; any domain user reading SYSVOL can decrypt these credentials instantly.")
                .Fix("Delete the offending GPP XML, change the exposed passwords, and use LAPS instead.");

            string[] files;
            try
            {
                if (!Directory.Exists(policies))
                {
                    ctx.Log?.Invoke("    [!] SYSVOL not reachable at " + policies + " (uses current session credentials).");
                    yield break;
                }
                files = Directory.GetFiles(policies, "*.xml", SearchOption.AllDirectories);
            }
            catch (Exception ex)
            {
                ctx.Log?.Invoke("    [!] SYSVOL scan skipped: " + ex.Message);
                yield break;
            }

            foreach (var file in files)
            {
                string text;
                try { text = File.ReadAllText(file); }
                catch { continue; }
                if (text.IndexOf("cpassword", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    text.IndexOf("cpassword=\"\"", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    CheckUtil.AddDetail(gpp, file.Replace(policies, "...\\Policies"));
                }
            }

            if (gpp.Details.Count > 0) yield return gpp;

            // ---- logon/startup scripts defined by GPOs ----
            var scripts = new Finding("V-GpoLogonScripts", Category.Anomalies, Severity.Low, 4,
                "GPO logon/startup scripts configured")
                .Why("Scripts pushed by GPO run on clients; if they reference a writable or external path, that path becomes a code-execution vector for everyone the GPO targets.")
                .Fix("Review each script path; ensure it lives on SYSVOL and is not writable by non-admins.");
            foreach (var ini in SafeGetFiles(policies, "*scripts.ini"))
            {
                string text;
                try { text = File.ReadAllText(ini); } catch { continue; }
                foreach (var line in text.Split('\n'))
                {
                    string t = line.Trim();
                    if (t.StartsWith("CmdLine", StringComparison.OrdinalIgnoreCase) && t.Contains("="))
                    {
                        string cmd = t.Substring(t.IndexOf('=') + 1).Trim();
                        CheckUtil.AddDetail(scripts, GpoGuid(ini) + " : " + cmd +
                            (cmd.StartsWith("\\\\") ? " [external UNC]" : ""));
                    }
                }
            }
            if (scripts.Details.Count > 0) yield return scripts;

            // ---- Restricted Groups managing privileged membership ----
            var restricted = new Finding("V-RestrictedGroups", Category.Anomalies, Severity.Medium, 8,
                "GPO Restricted Groups manage group membership")
                .Why("Restricted Groups push membership to targeted machines; pointing them at Administrators is a common persistence and lateral-movement technique.")
                .Fix("Confirm each Restricted Groups assignment is intended, especially those touching local Administrators.");
            var kerberos = new Finding("V-KerberosPolicy", Category.Anomalies, Severity.Low, 4,
                "Long Kerberos ticket lifetimes")
                .Why("Long TGT lifetime/renewal windows keep stolen or forged tickets (e.g. Golden/Silver) usable for longer.")
                .Fix("Keep MaxTicketAge at 10 hours and MaxRenewAge at 7 days unless there is a specific need.");

            foreach (var inf in SafeGetFiles(policies, "GptTmpl.inf"))
            {
                string text;
                try { text = File.ReadAllText(inf); } catch { continue; }
                string section = "";
                foreach (var line in text.Split('\n'))
                {
                    string t = line.Trim();
                    if (t.StartsWith("["))
                    {
                        section = t;
                        continue;
                    }
                    if (t.Length == 0 || !t.Contains("=")) continue;

                    if (section.Equals("[Group Membership]", StringComparison.OrdinalIgnoreCase))
                    {
                        bool admins = t.IndexOf("S-1-5-32-544", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                      t.IndexOf("Administrators", StringComparison.OrdinalIgnoreCase) >= 0;
                        CheckUtil.AddDetail(restricted, GpoGuid(inf) + " : " + t + (admins ? " [ADMINISTRATORS]" : ""));
                    }
                    else if (section.Equals("[Kerberos Policy]", StringComparison.OrdinalIgnoreCase))
                    {
                        string key = t.Substring(0, t.IndexOf('=')).Trim();
                        int val = int.TryParse(t.Substring(t.IndexOf('=') + 1).Trim(), out var p) ? p : 0;
                        if (key.Equals("MaxTicketAge", StringComparison.OrdinalIgnoreCase) && val > 10)
                            CheckUtil.AddDetail(kerberos, GpoGuid(inf) + " : MaxTicketAge=" + val + "h (recommend 10)");
                        if (key.Equals("MaxRenewAge", StringComparison.OrdinalIgnoreCase) && val > 7)
                            CheckUtil.AddDetail(kerberos, GpoGuid(inf) + " : MaxRenewAge=" + val + "d (recommend 7)");
                    }
                }
            }
            if (restricted.Details.Count > 0) yield return restricted;
            if (kerberos.Details.Count > 0) yield return kerberos;
        }

        private static string[] SafeGetFiles(string root, string pattern)
        {
            try { return Directory.GetFiles(root, pattern, SearchOption.AllDirectories); }
            catch { return new string[0]; }
        }

        // Extract the {GUID} of the GPO from a SYSVOL path under \Policies\.
        private static string GpoGuid(string path)
        {
            const string marker = @"\Policies\";
            int i = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (i < 0) return path;
            int start = i + marker.Length;
            int end = path.IndexOf('\\', start);
            return end > start ? path.Substring(start, end - start) : path.Substring(start);
        }
    }
}
