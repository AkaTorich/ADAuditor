using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // SYSVOL content: GPP passwords (MS14-025 / cpassword), GPO scripts, Restricted Groups,
    // Kerberos policy, dangerous user-rights assignments and GPO folder permissions.
    // Read over SMB with the current Windows session credentials.
    public sealed class SysvolChecks : ICheck
    {
        public string Name => "SYSVOL / GPP";

        private static readonly Regex CPassword = new Regex("cpassword=\"[^\"]+\"", RegexOptions.IgnoreCase);
        private static readonly Regex ScriptCmd = new Regex(@"^\d+CmdLine\s*=", RegexOptions.IgnoreCase);

        // User rights that amount to SYSTEM / domain-level control on the hosts the GPO targets.
        private static readonly string[] DangerousRights =
        {
            "SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege", "SeTcbPrivilege", "SeCreateTokenPrivilege",
            "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"
        };

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            // Prefer the server the user pointed at (DC name or IP) so SYSVOL works without DNS.
            string host = !string.IsNullOrEmpty(ctx.Server) ? ctx.Server : ctx.DomainDns;
            if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(ctx.DomainDns)) yield break;

            string policies = @"\\" + host + @"\SYSVOL\" + ctx.DomainDns + @"\Policies";
            string domSid = ctx.DomainSid?.Value ?? "";

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
                if (CPassword.IsMatch(text))
                    CheckUtil.AddDetail(gpp, file.Replace(policies, "...\\Policies"));
            }

            if (gpp.Details.Count > 0) yield return gpp;

            // ---- logon/startup scripts defined by GPOs (scripts.ini / psscripts.ini) ----
            var scripts = new Finding("V-GpoLogonScripts", Category.Anomalies, Severity.Low, 4,
                "GPO logon/startup scripts configured")
                .Why("Scripts pushed by GPO run on clients; if they reference a writable or external path, that path becomes a code-execution vector for everyone the GPO targets.")
                .Fix("Review each script path; ensure it lives on SYSVOL and is not writable by non-admins.");
            foreach (var ini in SafeGetFiles(policies, "*scripts.ini"))
            {
                string text;
                try { text = File.ReadAllText(ini); } catch { continue; }
                string section = "";
                foreach (var line in text.Split('\n'))
                {
                    string t = line.Trim();
                    if (t.StartsWith("[")) { section = t.Trim('[', ']'); continue; }
                    if (!ScriptCmd.IsMatch(t)) continue;
                    string cmd = t.Substring(t.IndexOf('=') + 1).Trim();
                    if (cmd.Length == 0) continue;
                    CheckUtil.AddDetail(scripts, GpoGuid(ini) + " [" + section + "] : " + cmd +
                        (cmd.StartsWith("\\\\") ? " [external UNC]" : ""));
                }
            }
            if (scripts.Details.Count > 0) yield return scripts;

            // ---- GptTmpl.inf: Restricted Groups, Kerberos policy, user rights ----
            var restricted = new Finding("V-RestrictedGroups", Category.Anomalies, Severity.Medium, 8,
                "GPO Restricted Groups manage group membership")
                .Why("Restricted Groups push membership to targeted machines; pointing them at Administrators is a common persistence and lateral-movement technique.")
                .Fix("Confirm each Restricted Groups assignment is intended, especially those touching local Administrators.");
            var kerberos = new Finding("V-KerberosPolicy", Category.Anomalies, Severity.Low, 4,
                "Long Kerberos ticket lifetimes")
                .Why("Long TGT lifetime/renewal windows keep stolen or forged tickets (e.g. Golden/Silver) usable for longer.")
                .Fix("Keep MaxTicketAge at 10 hours and MaxRenewAge at 7 days unless there is a specific need.");
            var rights = new Finding("V-PrivilegeRights", Category.Anomalies, Severity.High, 14,
                "GPO grants dangerous user rights to broad principals")
                .Why("Rights such as SeDebug, SeBackup/SeRestore, SeLoadDriver, SeImpersonate or SeEnableDelegation given to Everyone / Domain Users let any user become SYSTEM (or abuse delegation) on every host the GPO applies to.")
                .Fix("Remove broad principals from these user rights assignments.");
            var broad = BroadPrincipals(domSid);

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
                    string key = t.Substring(0, t.IndexOf('=')).Trim();
                    string val = t.Substring(t.IndexOf('=') + 1).Trim();

                    if (section.Equals("[Group Membership]", StringComparison.OrdinalIgnoreCase))
                    {
                        if (val.Length == 0) continue;
                        bool admins = t.IndexOf("S-1-5-32-544", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                      t.IndexOf("Administrators", StringComparison.OrdinalIgnoreCase) >= 0;
                        CheckUtil.AddDetail(restricted, GpoGuid(inf) + " : " + t + (admins ? " [ADMINISTRATORS]" : ""));
                    }
                    else if (section.Equals("[Kerberos Policy]", StringComparison.OrdinalIgnoreCase))
                    {
                        int n = int.TryParse(val, out var p) ? p : 0;
                        if (key.Equals("MaxTicketAge", StringComparison.OrdinalIgnoreCase) && n > 10)
                            CheckUtil.AddDetail(kerberos, GpoGuid(inf) + " : MaxTicketAge=" + n + "h (recommend 10)");
                        if (key.Equals("MaxRenewAge", StringComparison.OrdinalIgnoreCase) && n > 7)
                            CheckUtil.AddDetail(kerberos, GpoGuid(inf) + " : MaxRenewAge=" + n + "d (recommend 7)");
                    }
                    else if (section.Equals("[Privilege Rights]", StringComparison.OrdinalIgnoreCase) &&
                             Array.Exists(DangerousRights, r => r.Equals(key, StringComparison.OrdinalIgnoreCase)))
                    {
                        foreach (var raw in val.Split(','))
                        {
                            string who = raw.Trim().TrimStart('*');
                            if (broad.TryGetValue(who, out var label))
                                CheckUtil.AddDetail(rights, GpoGuid(inf) + " : " + key + " -> " + label);
                        }
                    }
                }
            }
            if (restricted.Details.Count > 0) yield return restricted;
            if (kerberos.Details.Count > 0) yield return kerberos;
            if (rights.Details.Count > 0) yield return rights;

            // ---- GPO folders writable by non-admins (file-level GPO takeover) ----
            var folderWrite = new Finding("V-GpoFolderWritable", Category.Anomalies, Severity.High, 14,
                "GPO folders in SYSVOL writable by non-admins")
                .Why("Whoever can write a GPO's SYSVOL folder can change its scripts, scheduled tasks and settings - code execution on every computer or user the GPO targets, even if the LDAP object is locked down.")
                .Fix("Reset the GPO folder permissions (GPMC 'Restore default permissions' / sync with the GPO's delegation).");
            var defaults = CheckUtil.DefaultPrivSids(domSid);
            const FileSystemRights writeMask = FileSystemRights.WriteData | FileSystemRights.AppendData |
                FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
                FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes;
            string[] gpoDirs;
            try { gpoDirs = Directory.GetDirectories(policies); } catch { gpoDirs = new string[0]; }
            foreach (var dir in gpoDirs)
            {
                AuthorizationRuleCollection rules;
                try { rules = Directory.GetAccessControl(dir).GetAccessRules(true, true, typeof(SecurityIdentifier)); }
                catch { continue; }
                foreach (FileSystemAccessRule rule in rules)
                {
                    if (rule.AccessControlType != AccessControlType.Allow) continue;
                    if ((rule.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
                    string sid = rule.IdentityReference.Value;
                    if (defaults.Contains(sid)) continue;
                    if ((rule.FileSystemRights & writeMask) != 0)
                        CheckUtil.AddDetail(folderWrite, CheckUtil.TranslateSid(sid) + " -> " + Path.GetFileName(dir) +
                            " (" + rule.FileSystemRights + ")");
                }
            }
            if (folderWrite.Details.Count > 0) yield return folderWrite;
        }

        // SIDs and literal names (as they may appear in GptTmpl.inf) of everyone-style principals.
        private static Dictionary<string, string> BroadPrincipals(string domSid)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "S-1-1-0", "Everyone" }, { "Everyone", "Everyone" },
                { "S-1-5-7", "Anonymous Logon" },
                { "S-1-5-11", "Authenticated Users" }, { "Authenticated Users", "Authenticated Users" },
                { "S-1-5-32-545", "BUILTIN\\Users" }, { "Users", "BUILTIN\\Users" },
                { "Domain Users", "Domain Users" }, { "Domain Computers", "Domain Computers" }
            };
            if (!string.IsNullOrEmpty(domSid))
            {
                d[domSid + "-513"] = "Domain Users";
                d[domSid + "-515"] = "Domain Computers";
            }
            return d;
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
