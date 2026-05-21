using System.Collections.Generic;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Kerberos delegation abuse and offline-crackable ticket exposure.
    public sealed class DelegationChecks : ICheck
    {
        public string Name => "Kerberos / Delegation";

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string baseDn = ctx.DefaultNamingContext;
            string enabled = "(!" + LdapBit.HasFlag("userAccountControl", (long)Uac.AccountDisabled) + ")";
            string notDc = "(!" + LdapBit.HasFlag("userAccountControl", (long)Uac.ServerTrustAccount) + ")";

            // ---- unconstrained delegation (excluding DCs) ----
            var unconstrained = new Finding("A-Unconstrained", Category.Anomalies, Severity.Critical, 25,
                "Unconstrained Kerberos delegation enabled")
                .Why("Any host trusted for unconstrained delegation caches TGTs of every user who connects, including domain admins - a direct path to full compromise (printer-bug coercion makes it trivial).")
                .Fix("Replace with constrained/RBCD delegation and mark sensitive accounts as 'Account is sensitive and cannot be delegated'.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&" + LdapBit.HasFlag("userAccountControl", (long)Uac.TrustedForDelegation) + notDc + ")",
                "sAMAccountName")))
                CheckUtil.AddDetail(unconstrained, CheckUtil.Sam(r));
            if (unconstrained.Details.Count > 0) yield return unconstrained;

            // ---- constrained delegation ----
            var constrained = new Finding("A-Constrained", Category.Anomalies, Severity.Medium, 8,
                "Constrained delegation configured")
                .Why("Constrained delegation (msDS-AllowedToDelegateTo) lets the account impersonate users to the listed services; protocol transition makes it stronger.")
                .Fix("Audit each delegation target; remove unneeded entries.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(msDS-AllowedToDelegateTo=*)", "sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl")))
            {
                string sam = CheckUtil.Sam(r);
                bool pt = (AuditContext.Int64Of(r, "userAccountControl") & (long)Uac.TrustedToAuthForDelegation) != 0;
                var targets = r.Properties["msDS-AllowedToDelegateTo"];
                string first = targets.Count > 0 ? targets[0].ToString() : "";
                CheckUtil.AddDetail(constrained, sam + (pt ? " [protocol-transition]" : "") + " -> " + first +
                    (targets.Count > 1 ? " (+" + (targets.Count - 1) + ")" : ""));
            }
            if (constrained.Details.Count > 0) yield return constrained;

            // ---- resource-based constrained delegation ----
            var rbcd = new Finding("A-RBCD", Category.Anomalies, Severity.High, 12,
                "Resource-based constrained delegation set on objects")
                .Why("msDS-AllowedToActOnBehalfOfOtherIdentity is writable by anyone with object control; attackers abuse it to impersonate any user on the target.")
                .Fix("Verify each principal allowed to act on behalf; remove unexpected entries.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)", "sAMAccountName")))
                CheckUtil.AddDetail(rbcd, CheckUtil.Sam(r));
            if (rbcd.Details.Count > 0) yield return rbcd;

            // ---- Kerberoastable user accounts (all) ----
            var kerberoast = new Finding("A-Kerberoast", Category.Anomalies, Severity.High, 12,
                "User accounts with SPNs (Kerberoastable)")
                .Why("Any authenticated user can request service tickets for these accounts and crack them offline.")
                .Fix("Use gMSA, enforce 25+ char random passwords on service accounts, and monitor TGS requests.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))" + enabled + ")",
                "sAMAccountName", "servicePrincipalName")))
            {
                var spns = r.Properties["servicePrincipalName"];
                CheckUtil.AddDetail(kerberoast, CheckUtil.Sam(r) + " [" + (spns.Count > 0 ? spns[0].ToString() : "") + "]");
            }
            if (kerberoast.Details.Count > 0) yield return kerberoast;

            // ---- AS-REP roastable (all) ----
            var asrep = new Finding("A-AsrepRoast", Category.Anomalies, Severity.High, 12,
                "Accounts with Kerberos pre-authentication disabled (AS-REP roastable)")
                .Why("Without pre-auth, anyone can request an AS-REP for the account and crack its password offline.")
                .Fix("Re-enable pre-authentication on every account.");
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectCategory=person)(objectClass=user)" + LdapBit.HasFlag("userAccountControl", (long)Uac.DontRequirePreauth) + ")",
                "sAMAccountName")))
                CheckUtil.AddDetail(asrep, CheckUtil.Sam(r));
            if (asrep.Details.Count > 0) yield return asrep;
        }
    }
}
