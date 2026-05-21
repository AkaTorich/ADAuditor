using System;
using System.Collections.Generic;
using ADAuditor.Checks;

namespace ADAuditor.Core
{
    // One audit rule (or a group of related rules) implements this.
    public interface ICheck
    {
        string Name { get; }
        IEnumerable<Finding> Run(AuditContext ctx);
    }

    public sealed class AuditEngine
    {
        private readonly List<ICheck> _checks = new List<ICheck>
        {
            new StaleChecks(),
            new PrivilegedChecks(),
            new DelegationChecks(),
            new TrustChecks(),
            new AnomalyChecks(),
            new AclChecks(),
            new AdvancedAclChecks(),
            new GpoChecks(),
            new CertChecks(),
            new LdapExtraChecks(),
            new Tier3GraphChecks(),   // after Delegation + Cert so it can fold in their vector edges
            new SysvolChecks(),
            new Tier2HostChecks(),
            new Tier2MemberChecks(),
            new Tier2CaChecks()
        };

        public AuditReport Run(AuditContext ctx)
        {
            var report = new AuditReport
            {
                GeneratedUtc = DateTime.UtcNow,
                DomainName = ctx.DomainDns,
                DomainDn = ctx.DefaultNamingContext,
                ForestName = ctx.ForestDns,
                DomainController = ctx.DnsHostName,
                DomainFunctionalLevel = ctx.DomainFunctionality,
                ForestFunctionalLevel = ctx.ForestFunctionality
            };

            int idx = 0;
            foreach (var check in _checks)
            {
                idx++;
                ctx.Log?.Invoke($"[*] ({idx}/{_checks.Count}) Running module: {check.Name} ...");
                try
                {
                    foreach (var f in check.Run(ctx))
                    {
                        report.Findings.Add(f);
                        ctx.Log?.Invoke($"    [{SevTag(f.Severity)}] {f.Id}: {f.Title}" +
                                        (f.Details.Count > 0 ? $" ({f.Details.Count})" : ""));
                    }
                }
                catch (Exception ex)
                {
                    ctx.Log?.Invoke($"    [!] module {check.Name} failed: {ex.Message}");
                }
            }

            report.AttackGraph = ctx.AttackGraph;

            ctx.Log?.Invoke("");
            ctx.Log?.Invoke($"[+] Audit complete. {report.Findings.Count} findings. Global risk score: {report.GlobalScore()}/100");
            return report;
        }

        private static string SevTag(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return "CRIT";
                case Severity.High: return "HIGH";
                case Severity.Medium: return "MED ";
                case Severity.Low: return "LOW ";
                default: return "INFO";
            }
        }
    }
}
