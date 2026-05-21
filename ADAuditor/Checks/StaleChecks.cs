using System.Collections.Generic;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Stale / hygiene problems: dormant accounts, weak account flags, legacy OS.
    public sealed class StaleChecks : ICheck
    {
        public string Name => "Stale Objects";

        private const int UserInactiveDays = 180;
        private const int ComputerInactiveDays = 90;
        private const int PwdAgeWarnDays = 1000;

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            var baseDn = ctx.DefaultNamingContext;
            string notDisabled = "(!" + LdapBit.HasFlag("userAccountControl", (long)Uac.AccountDisabled) + ")";

            // ---- enabled users, evaluated in code ----
            var inactiveUsers = new Finding("S-InactiveUsers", Category.StaleObjects, Severity.Medium, 10,
                "Dormant but enabled user accounts")
                .Why("Unused enabled accounts widen the attack surface and are prime targets for password spraying.")
                .Fix("Disable or remove accounts inactive beyond " + UserInactiveDays + " days.");

            var neverLogged = new Finding("S-NeverLoggedOn", Category.StaleObjects, Severity.Low, 5,
                "Enabled accounts that have never logged on")
                .Why("An account created but never used is often a provisioning leftover or a planted backdoor.")
                .Fix("Disable accounts that are not actually in use.");

            var neverExpire = new Finding("S-PwdNeverExpires", Category.StaleObjects, Severity.Medium, 10,
                "Users with non-expiring passwords")
                .Why("Passwords that never expire stay valid forever once leaked.")
                .Fix("Remove DONT_EXPIRE_PASSWORD; use managed/service accounts where rotation is hard.");

            var notReqd = new Finding("S-PasswdNotReqd", Category.StaleObjects, Severity.High, 15,
                "Accounts that may have an empty password (PASSWD_NOTREQD)")
                .Why("These accounts can have a blank password and are trivially compromised.")
                .Fix("Clear the PASSWD_NOTREQD flag and enforce the password policy.");

            var reversible = new Finding("S-ReversiblePwd", Category.StaleObjects, Severity.High, 15,
                "Accounts storing reversible (cleartext-recoverable) passwords")
                .Why("ENCRYPTED_TEXT_PWD_ALLOWED lets the DC store passwords that can be decrypted to cleartext.")
                .Fix("Disable reversible encryption for these accounts and reset their passwords.");

            var desOnly = new Finding("S-DesOnly", Category.StaleObjects, Severity.Medium, 8,
                "Accounts restricted to DES Kerberos keys")
                .Why("DES is cryptographically broken; such tickets are cheaply crackable.")
                .Fix("Clear USE_DES_KEY_ONLY and re-enable AES.");

            var oldPwd = new Finding("S-OldPassword", Category.StaleObjects, Severity.Low, 5,
                "Enabled accounts with very old passwords")
                .Why("Passwords older than " + PwdAgeWarnDays + " days greatly increase exposure window.")
                .Fix("Force a password change on these accounts.");

            var mustChange = new Finding("S-MustChange", Category.StaleObjects, Severity.Low, 3,
                "Enabled accounts that have never set a password (pwdLastSet=0)")
                .Why("pwdLastSet=0 means the account must set a password at next logon - often a provisioned but unused/forgotten account.")
                .Fix("Disable accounts that should not be active.");

            var expired = new Finding("S-Expired", Category.StaleObjects, Severity.Low, 3,
                "Enabled accounts whose expiration date has already passed")
                .Why("An expired-but-enabled account is dormant yet still a valid target.")
                .Fix("Disable or remove expired accounts.");

            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectCategory=person)(objectClass=user)" + notDisabled + ")",
                "sAMAccountName", "userAccountControl", "lastLogonTimestamp", "pwdLastSet", "accountExpires", "whenCreated")))
            {
                string sam = CheckUtil.Sam(r);
                long uac = AuditContext.Int64Of(r, "userAccountControl");
                long llt = AuditContext.Int64Of(r, "lastLogonTimestamp");
                long pls = AuditContext.Int64Of(r, "pwdLastSet");
                long exp = AuditContext.Int64Of(r, "accountExpires");

                if (llt == 0)
                {
                    // never logged on - flag only if not freshly created (>30 days old)
                    var created = WhenCreated(r);
                    if (created == null || created.Value < System.DateTime.UtcNow.AddDays(-30))
                        CheckUtil.AddDetail(neverLogged, sam +
                            (created != null ? " (created: " + created.Value.ToString("yyyy-MM-dd") + ")" : ""));
                }
                else
                {
                    int idle = CheckUtil.DaysSince(llt);
                    if (idle > UserInactiveDays)
                        CheckUtil.AddDetail(inactiveUsers, sam + " (last logon: " + CheckUtil.FmtDate(llt) + ")");
                }

                if (pls == 0)
                    CheckUtil.AddDetail(mustChange, sam);

                // accountExpires: 0 and 0x7FFFFFFFFFFFFFFF both mean "never"
                if (exp != 0 && exp != long.MaxValue)
                {
                    var when = AuditContext.FileTime(exp);
                    if (when != null && when.Value < System.DateTime.UtcNow)
                        CheckUtil.AddDetail(expired, sam + " (expired: " + when.Value.ToString("yyyy-MM-dd") + ")");
                }

                if ((uac & (long)Uac.DontExpirePassword) != 0)
                    CheckUtil.AddDetail(neverExpire, sam);
                if ((uac & (long)Uac.PasswdNotReqd) != 0)
                    CheckUtil.AddDetail(notReqd, sam);
                if ((uac & (long)Uac.EncryptedTextPwdAllowed) != 0)
                    CheckUtil.AddDetail(reversible, sam);
                if ((uac & (long)Uac.UseDesKeyOnly) != 0)
                    CheckUtil.AddDetail(desOnly, sam);

                if ((uac & (long)Uac.DontExpirePassword) == 0)
                {
                    int age = CheckUtil.DaysSince(pls);
                    if (age > PwdAgeWarnDays)
                        CheckUtil.AddDetail(oldPwd, sam + " (set: " + CheckUtil.FmtDate(pls) + ")");
                }
            }

            if (inactiveUsers.Details.Count > 0) yield return inactiveUsers;
            if (neverLogged.Details.Count > 0) yield return neverLogged;
            if (neverExpire.Details.Count > 0) yield return neverExpire;
            if (notReqd.Details.Count > 0) yield return notReqd;
            if (reversible.Details.Count > 0) yield return reversible;
            if (desOnly.Details.Count > 0) yield return desOnly;
            if (oldPwd.Details.Count > 0) yield return oldPwd;
            if (mustChange.Details.Count > 0) yield return mustChange;
            if (expired.Details.Count > 0) yield return expired;

            // ---- computers ----
            var inactiveComputers = new Finding("S-InactiveComputers", Category.StaleObjects, Severity.Low, 5,
                "Dormant but enabled computer accounts")
                .Why("Stale machine accounts can be reactivated or abused for lateral movement.")
                .Fix("Disable/remove computer objects inactive beyond " + ComputerInactiveDays + " days.");

            var legacyOs = new Finding("S-LegacyOS", Category.StaleObjects, Severity.High, 15,
                "Computers running end-of-life operating systems")
                .Why("Unsupported OS versions receive no security patches and are easy footholds.")
                .Fix("Decommission or isolate legacy hosts.");

            var machinePwd = new Finding("S-MachinePassword", Category.StaleObjects, Severity.Low, 4,
                "Computers whose machine password has not rotated")
                .Why("Domain-joined computers rotate their password every 30 days; a much older one suggests an abandoned or offline-joined object.")
                .Fix("Verify these hosts still exist; remove orphaned computer accounts.");

            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectCategory=computer)" + notDisabled + ")",
                "sAMAccountName", "lastLogonTimestamp", "operatingSystem", "pwdLastSet")))
            {
                string sam = CheckUtil.Sam(r);
                long llt = AuditContext.Int64Of(r, "lastLogonTimestamp");
                int idle = CheckUtil.DaysSince(llt);
                if (idle < 0 || idle > ComputerInactiveDays)
                    CheckUtil.AddDetail(inactiveComputers, sam + " (last logon: " + CheckUtil.FmtDate(llt) + ")");

                string os = AuditContext.Str(r, "operatingSystem");
                if (IsLegacyOs(os))
                    CheckUtil.AddDetail(legacyOs, sam + " -> " + os);

                long mpls = AuditContext.Int64Of(r, "pwdLastSet");
                int mage = CheckUtil.DaysSince(mpls);
                if (mage > 90 && idle >= 0 && idle <= ComputerInactiveDays) // still active but pwd not rotating
                    CheckUtil.AddDetail(machinePwd, sam + " (machine pwd set: " + CheckUtil.FmtDate(mpls) + ")");
            }

            if (inactiveComputers.Details.Count > 0) yield return inactiveComputers;
            if (legacyOs.Details.Count > 0) yield return legacyOs;
            if (machinePwd.Details.Count > 0) yield return machinePwd;
        }

        private static System.DateTime? WhenCreated(System.DirectoryServices.SearchResult r)
        {
            if (r.Properties.Contains("whenCreated") && r.Properties["whenCreated"].Count > 0)
            {
                var v = r.Properties["whenCreated"][0];
                if (v is System.DateTime dt) return dt.ToUniversalTime();
            }
            return null;
        }

        private static bool IsLegacyOs(string os)
        {
            if (string.IsNullOrEmpty(os)) return false;
            os = os.ToLowerInvariant();
            string[] eol = { "2000", "windows xp", "2003", "vista", "windows 7", "windows 8",
                             "2008", "server 2012" };
            foreach (var token in eol)
                if (os.Contains(token)) return true;
            return false;
        }
    }
}
