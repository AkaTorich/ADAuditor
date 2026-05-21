using System.Collections.Generic;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Domain/forest trust relationships and their filtering posture.
    public sealed class TrustChecks : ICheck
    {
        public string Name => "Trusts";

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string sysDn = "CN=System," + ctx.DefaultNamingContext;

            var inventory = new Finding("T-Inventory", Category.Trusts, Severity.Info, 0,
                "Trust relationships")
                .Why("Trusts extend the authentication boundary; each one expands who can request access into this domain.")
                .Fix("Remove unused trusts; prefer one-way and non-transitive where possible.");

            var sidFilterOff = new Finding("T-SidFilterDisabled", Category.Trusts, Severity.High, 20,
                "Trust without SID filtering / quarantine")
                .Why("Without SID filtering an attacker in the trusted domain can inject SID history to impersonate privileged principals in this domain.")
                .Fix("Enable SID filtering (quarantine) on external trusts; review forest trust SID filtering.");

            var rc4Trust = new Finding("T-Rc4Trust", Category.Trusts, Severity.Low, 4,
                "Trust still permits RC4 encryption")
                .Why("RC4 trust keys are weaker than AES and ease ticket forging across the trust.")
                .Fix("Enable AES on the trust where both sides support it.");

            var noSelective = new Finding("T-NoSelectiveAuth", Category.Trusts, Severity.Medium, 8,
                "External trust without selective authentication")
                .Why("Without selective auth, every principal in the trusted domain is treated as Authenticated Users here, widening access.")
                .Fix("Enable selective authentication on external/forest trusts.");

            int count = 0;
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(sysDn,
                "(objectClass=trustedDomain)",
                "trustPartner", "trustDirection", "trustType", "trustAttributes", "flatName")))
            {
                count++;
                string partner = AuditContext.Str(r, "trustPartner");
                int dir = (int)AuditContext.Int64Of(r, "trustDirection");
                int type = (int)AuditContext.Int64Of(r, "trustType");
                int attrs = (int)AuditContext.Int64Of(r, "trustAttributes");
                var ta = (TrustAttributes)attrs;

                CheckUtil.AddDetail(inventory,
                    partner + " | dir=" + DirName(dir) + " | type=" + TypeName(type) + " | attrs=" + ta);

                bool withinForest = (ta & TrustAttributes.WithinForest) != 0;
                bool forestTransitive = (ta & TrustAttributes.ForestTransitive) != 0;
                bool quarantined = (ta & TrustAttributes.QuarantinedDomain) != 0;

                // External (cross-domain, not intra-forest) trust should be quarantined.
                if (!withinForest && !forestTransitive && !quarantined)
                    CheckUtil.AddDetail(sidFilterOff, partner + " (external trust, quarantine OFF)");

                if ((ta & TrustAttributes.UsesRc4Encryption) != 0)
                    CheckUtil.AddDetail(rc4Trust, partner);

                // External (non-intra-forest) trust without selective authentication
                if (!withinForest && (ta & TrustAttributes.CrossOrganization) == 0)
                    CheckUtil.AddDetail(noSelective, partner);
            }

            if (count > 0) yield return inventory;
            if (sidFilterOff.Details.Count > 0) yield return sidFilterOff;
            if (rc4Trust.Details.Count > 0) yield return rc4Trust;
            if (noSelective.Details.Count > 0) yield return noSelective;

            // ---- trust account (DOMAIN$) password age ----
            var trustPwd = new Finding("T-TrustPasswordAge", Category.Trusts, Severity.Medium, 8,
                "Trust passwords not rotated recently")
                .Why("Trust keys normally rotate every 30 days; a stale key keeps inter-realm ticket forgery viable for longer.")
                .Fix("Investigate why the trust password has not rotated (broken trust / disabled rotation).");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(ctx.DefaultNamingContext,
                "(&(objectClass=user)" + LdapBit.HasFlag("userAccountControl", (long)Uac.InterdomainTrustAccount) + ")",
                "sAMAccountName", "pwdLastSet")))
            {
                long pls = AuditContext.Int64Of(r, "pwdLastSet");
                int age = CheckUtil.DaysSince(pls);
                if (age > 180 || age < 0)
                    CheckUtil.AddDetail(trustPwd, CheckUtil.Sam(r) + " (set: " + CheckUtil.FmtDate(pls) + ")");
            }
            if (trustPwd.Details.Count > 0) yield return trustPwd;
        }

        private static string DirName(int d)
        {
            switch (d) { case 1: return "inbound"; case 2: return "outbound"; case 3: return "bidirectional"; default: return "disabled"; }
        }

        private static string TypeName(int t)
        {
            switch (t) { case 1: return "downlevel-NT"; case 2: return "AD"; case 3: return "MIT-Kerberos"; case 4: return "DCE"; default: return t.ToString(); }
        }
    }
}
