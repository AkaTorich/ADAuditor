using System.Collections.Generic;

namespace ADAuditor.Core
{
    // PingCastle-style risk domains
    public enum Category
    {
        StaleObjects,
        PrivilegedAccounts,
        Trusts,
        Anomalies
    }

    public enum Severity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    // A single audit rule outcome
    public sealed class Finding
    {
        public string Id { get; set; }              // short rule code, e.g. "P-Krbtgt"
        public Category Category { get; set; }
        public Severity Severity { get; set; }
        public string Title { get; set; }
        public string Rationale { get; set; }       // why it matters / attack relevance
        public string Recommendation { get; set; }
        public int Points { get; set; }             // contribution to the category score
        public List<string> Details { get; set; } = new List<string>(); // affected objects/values

        public Finding(string id, Category category, Severity severity, int points, string title)
        {
            Id = id;
            Category = category;
            Severity = severity;
            Points = points;
            Title = title;
        }

        public Finding Detail(string line)
        {
            if (!string.IsNullOrEmpty(line)) Details.Add(line);
            return this;
        }

        public Finding Why(string rationale) { Rationale = rationale; return this; }
        public Finding Fix(string recommendation) { Recommendation = recommendation; return this; }
    }

    // Whole-run output
    public sealed class AuditReport
    {
        public string DomainName { get; set; }
        public string DomainDn { get; set; }
        public string ForestName { get; set; }
        public string DomainController { get; set; }
        public System.DateTime GeneratedUtc { get; set; }
        public int DomainFunctionalLevel { get; set; }
        public int ForestFunctionalLevel { get; set; }

        public List<Finding> Findings { get; } = new List<Finding>();

        // Optional attack-path subgraph for visualization (populated by Tier 3).
        public GraphModel AttackGraph { get; set; }

        // Per-category score, capped at 100; higher = worse
        public int Score(Category cat)
        {
            int sum = 0;
            foreach (var f in Findings)
                if (f.Category == cat) sum += f.Points;
            return sum > 100 ? 100 : sum;
        }

        public int GlobalScore()
        {
            int max = 0;
            foreach (Category c in System.Enum.GetValues(typeof(Category)))
            {
                int s = Score(c);
                if (s > max) max = s;
            }
            return max;
        }
    }
}
