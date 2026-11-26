using System;
using System.Globalization;
using System.Text;
using ADAuditor.Core;

namespace ADAuditor.Report
{
    // Machine-readable export: run metadata, scores, findings and the attack-path graph.
    public static class JsonReportWriter
    {
        public static string Build(AuditReport rep)
        {
            var sb = new StringBuilder();
            sb.Append("{\n");
            Prop(sb, "tool", "ADAuditor"); sb.Append(",\n");
            Prop(sb, "version", typeof(JsonReportWriter).Assembly.GetName().Version.ToString(3)); sb.Append(",\n");
            Prop(sb, "domain", rep.DomainName); sb.Append(",\n");
            Prop(sb, "domainDn", rep.DomainDn); sb.Append(",\n");
            Prop(sb, "forest", rep.ForestName); sb.Append(",\n");
            Prop(sb, "domainController", rep.DomainController); sb.Append(",\n");
            Prop(sb, "generatedUtc", rep.GeneratedUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)); sb.Append(",\n");
            sb.Append("  \"domainFunctionalLevel\": ").Append(rep.DomainFunctionalLevel).Append(",\n");
            sb.Append("  \"forestFunctionalLevel\": ").Append(rep.ForestFunctionalLevel).Append(",\n");

            sb.Append("  \"scores\": { \"global\": ").Append(rep.GlobalScore());
            foreach (Category c in Enum.GetValues(typeof(Category)))
                sb.Append(", ").Append(Str(c.ToString())).Append(": ").Append(rep.Score(c));
            sb.Append(" },\n");

            sb.Append("  \"findings\": [");
            for (int i = 0; i < rep.Findings.Count; i++)
            {
                var f = rep.Findings[i];
                sb.Append(i == 0 ? "\n" : ",\n").Append("    { ");
                sb.Append("\"id\": ").Append(Str(f.Id));
                sb.Append(", \"category\": ").Append(Str(f.Category.ToString()));
                sb.Append(", \"severity\": ").Append(Str(f.Severity.ToString()));
                sb.Append(", \"points\": ").Append(f.Points);
                sb.Append(", \"title\": ").Append(Str(f.Title));
                sb.Append(", \"rationale\": ").Append(Str(f.Rationale));
                sb.Append(", \"recommendation\": ").Append(Str(f.Recommendation));
                sb.Append(", \"details\": [");
                for (int d = 0; d < f.Details.Count; d++)
                    sb.Append(d == 0 ? "" : ", ").Append(Str(f.Details[d]));
                sb.Append("] }");
            }
            sb.Append(rep.Findings.Count > 0 ? "\n  ],\n" : "],\n");

            sb.Append("  \"attackGraph\": ");
            var g = rep.AttackGraph;
            if (g == null) sb.Append("null");
            else
            {
                sb.Append("{ \"nodes\": [");
                for (int i = 0; i < g.Nodes.Count; i++)
                {
                    var n = g.Nodes[i];
                    sb.Append(i == 0 ? "\n" : ",\n").Append("      { \"id\": ").Append(Str(n.Id))
                      .Append(", \"label\": ").Append(Str(n.Label))
                      .Append(", \"kind\": ").Append(Str(n.Kind))
                      .Append(", \"distance\": ").Append(n.Distance).Append(" }");
                }
                sb.Append("], \"edges\": [");
                for (int i = 0; i < g.Edges.Count; i++)
                {
                    var e = g.Edges[i];
                    sb.Append(i == 0 ? "\n" : ",\n").Append("      { \"from\": ").Append(Str(e.From))
                      .Append(", \"to\": ").Append(Str(e.To))
                      .Append(", \"type\": ").Append(Str(e.Type))
                      .Append(", \"breakPoint\": ").Append(e.Weak ? "true" : "false").Append(" }");
                }
                sb.Append("] }");
            }
            sb.Append("\n}\n");
            return sb.ToString();
        }

        private static void Prop(StringBuilder sb, string name, string value)
            => sb.Append("  ").Append(Str(name)).Append(": ").Append(Str(value));

        private static string Str(string s)
        {
            if (s == null) return "null";
            var sb = new StringBuilder(s.Length + 2);
            sb.Append('"');
            foreach (char ch in s)
            {
                switch (ch)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (ch < 0x20) sb.Append("\\u").Append(((int)ch).ToString("x4"));
                        else sb.Append(ch);
                        break;
                }
            }
            return sb.Append('"').ToString();
        }
    }
}
