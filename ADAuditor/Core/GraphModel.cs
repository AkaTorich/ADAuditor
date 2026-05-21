using System.Collections.Generic;

namespace ADAuditor.Core
{
    // Compact attack-path subgraph produced by Tier 3 for visualization.
    public sealed class GraphNode
    {
        public string Id { get; set; }       // SID
        public string Label { get; set; }     // sAMAccountName / display
        public string Kind { get; set; }      // "target" | "broad" | "source" | "mid"
        public int Distance { get; set; }      // hops to nearest tier-0 target (0 = target)
    }

    public sealed class GraphEdge
    {
        public string From { get; set; }
        public string To { get; set; }
        public string Type { get; set; }      // MemberOf, GenericAll, ...
        public bool Weak { get; set; }         // recommended break point on a path
    }

    public sealed class GraphModel
    {
        public List<GraphNode> Nodes { get; } = new List<GraphNode>();
        public List<GraphEdge> Edges { get; } = new List<GraphEdge>();
    }
}
