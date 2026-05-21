using System.Text;
using ADAuditor.Core;

namespace ADAuditor.Report
{
    // Exports the attack-path subgraph as Graphviz DOT (readable by any graph tool).
    public static class DotGraphWriter
    {
        public static string Build(GraphModel g)
        {
            var sb = new StringBuilder();
            sb.AppendLine("digraph ADAuditor {");
            sb.AppendLine("  rankdir=LR;");
            sb.AppendLine("  bgcolor=\"#050805\";");
            sb.AppendLine("  node [style=filled, fontname=\"Consolas\", fontcolor=\"#050805\", shape=box];");
            sb.AppendLine("  edge [fontname=\"Consolas\", fontsize=9];");

            if (g != null)
            {
                foreach (var n in g.Nodes)
                    sb.AppendLine("  \"" + Esc(n.Id) + "\" [label=\"" + Esc(n.Label) + "\", fillcolor=\"" +
                                  NodeColor(n.Kind) + "\"];");

                foreach (var e in g.Edges)
                {
                    string color = e.Weak ? "#FF3B30" : (e.Type == "MemberOf" ? "#2E6F42" : "#FFB000");
                    string pen = e.Weak ? "3.0" : "1.0";
                    sb.AppendLine("  \"" + Esc(e.From) + "\" -> \"" + Esc(e.To) + "\" [label=\"" + Esc(e.Type) +
                                  "\", color=\"" + color + "\", fontcolor=\"" + color + "\", penwidth=" + pen + "];");
                }
            }

            sb.AppendLine("}");
            return sb.ToString();
        }

        private static string NodeColor(string kind)
        {
            switch (kind)
            {
                case "target": return "#FF3B30";
                case "broad": return "#FF8C00";
                case "source": return "#33FF66";
                default: return "#1E8F3E";
            }
        }

        private static string Esc(string s)
        {
            return string.IsNullOrEmpty(s) ? "" : s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}
