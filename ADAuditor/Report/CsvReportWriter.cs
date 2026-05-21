using System.Text;
using ADAuditor.Core;

namespace ADAuditor.Report
{
    // One row per (finding, affected object); findings with no objects get a single row.
    public static class CsvReportWriter
    {
        public static string Build(AuditReport rep)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Domain,Generated,Category,Severity,Id,Title,Points,Detail,Rationale,Recommendation");
            string gen = rep.GeneratedUtc.ToString("yyyy-MM-dd HH:mm:ss");

            foreach (var f in rep.Findings)
            {
                if (f.Details.Count == 0)
                {
                    sb.AppendLine(Row(rep.DomainName, gen, f, ""));
                }
                else
                {
                    foreach (var d in f.Details)
                        sb.AppendLine(Row(rep.DomainName, gen, f, d));
                }
            }
            return sb.ToString();
        }

        private static string Row(string domain, string gen, Finding f, string detail)
        {
            return string.Join(",",
                Q(domain), Q(gen), Q(f.Category.ToString()), Q(f.Severity.ToString()),
                Q(f.Id), Q(f.Title), Q(f.Points.ToString()), Q(detail),
                Q(f.Rationale), Q(f.Recommendation));
        }

        // RFC 4180 field quoting.
        private static string Q(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            bool needs = s.IndexOf(',') >= 0 || s.IndexOf('"') >= 0 || s.IndexOf('\n') >= 0 || s.IndexOf('\r') >= 0;
            s = s.Replace("\"", "\"\"");
            return needs ? "\"" + s + "\"" : s;
        }
    }
}
