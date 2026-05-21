using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Tier 3: build a control graph (MemberOf + dangerous ACLs + DCSync) and find
    // the shortest escalation path from any non-privileged principal to tier-0
    // (Domain/Enterprise/Schema/BUILTIN Admins, krbtgt, the domain object).
    public sealed class Tier3GraphChecks : ICheck
    {
        public string Name => "Attack Paths (Tier 3)";

        private static readonly Guid ForceChangePwd = new Guid("00299570-246d-11d0-a768-00aa006e0529");
        private static readonly Guid MemberAttr = new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2");
        private static readonly Guid GetChanges = new Guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
        private static readonly Guid GetChangesAll = new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");

        private const int MaxPaths = 60;
        private const int MaxHops = 30;

        public IEnumerable<Finding> Run(AuditContext ctx)
        {
            string baseDn = ctx.DefaultNamingContext;
            string domSid = ctx.DomainSid?.Value ?? "";
            var defaults = CheckUtil.DefaultPrivSids(domSid);
            Guid? keyCred = CheckUtil.SchemaGuid(ctx, "msDS-KeyCredentialLink");

            var nameOf = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var dnToSid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var groupMembers = new List<(string groupSid, List<string> memberDns)>();
            var edges = new List<(string from, string to, string type)>();
            var hostToSid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var computers = new List<(string sid, string host)>();
            var constrained = new List<(string sid, List<string> spns)>();
            var unconstrained = new List<string>();

            // ---- pass 1: nodes, membership, ACL + delegation edges ----
            var s = CheckUtil.WithDacl(ctx.SubtreeSearcher(baseDn,
                "(|(objectClass=user)(objectClass=group))",
                "sAMAccountName", "distinguishedName", "objectSid", "objectClass", "member", "nTSecurityDescriptor",
                "userAccountControl", "dNSHostName", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity"));
            foreach (var r in CheckUtil.Enumerate(s))
            {
                var sidBytes = CheckUtil.Bytes(r, "objectSid");
                if (sidBytes == null) continue;
                string sid = new SecurityIdentifier(sidBytes, 0).Value;
                string dn = CheckUtil.Dn(r);
                string sam = CheckUtil.Sam(r);
                nameOf[sid] = !string.IsNullOrEmpty(sam) ? sam : ShortDn(dn);
                if (!string.IsNullOrEmpty(dn)) dnToSid[dn] = sid;
                bool isGroup = CheckUtil.HasClass(r, "group");
                bool isComputer = CheckUtil.HasClass(r, "computer");
                long uac = AuditContext.Int64Of(r, "userAccountControl");

                if (isComputer)
                {
                    string host = AuditContext.Str(r, "dNSHostName");
                    if (!string.IsNullOrEmpty(host)) { hostToSid[host] = sid; computers.Add((sid, host)); }
                    string flat = sam.EndsWith("$") ? sam.Substring(0, sam.Length - 1) : sam;
                    if (!string.IsNullOrEmpty(flat)) hostToSid[flat] = sid;
                }
                if ((uac & (long)Uac.TrustedForDelegation) != 0 && (uac & (long)Uac.ServerTrustAccount) == 0)
                    unconstrained.Add(sid);
                if (r.Properties.Contains("msDS-AllowedToDelegateTo") && r.Properties["msDS-AllowedToDelegateTo"].Count > 0)
                {
                    var spns = new List<string>();
                    foreach (var v in r.Properties["msDS-AllowedToDelegateTo"]) spns.Add(v?.ToString() ?? "");
                    constrained.Add((sid, spns));
                }
                var rbcd = CheckUtil.Bytes(r, "msDS-AllowedToActOnBehalfOfOtherIdentity");
                if (rbcd != null)
                {
                    try
                    {
                        var rsd = CheckUtil.ParseSd(rbcd);
                        foreach (ActiveDirectoryAccessRule ru in rsd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                        {
                            if (ru.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                            string p = ru.IdentityReference.Value;
                            if (defaults.Contains(p) || p == sid) continue;
                            edges.Add((p, sid, "AllowedToAct"));
                        }
                    }
                    catch { }
                }

                if (isGroup && r.Properties.Contains("member") && r.Properties["member"].Count > 0)
                {
                    var dns = new List<string>();
                    foreach (var m in r.Properties["member"]) dns.Add(m?.ToString() ?? "");
                    groupMembers.Add((sid, dns));
                }

                byte[] sdb = CheckUtil.Bytes(r, "nTSecurityDescriptor");
                if (sdb == null) continue;
                ActiveDirectorySecurity sd;
                try { sd = CheckUtil.ParseSd(sdb); } catch { continue; }

                var owner = sd.GetOwner(typeof(SecurityIdentifier))?.Value;
                if (owner != null && !defaults.Contains(owner) && owner != sid)
                    edges.Add((owner, sid, "Owns"));

                foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                    string c = rule.IdentityReference.Value;
                    if (defaults.Contains(c) || c == sid) continue;
                    var rights = rule.ActiveDirectoryRights;
                    var ot = rule.ObjectType;

                    if (CheckUtil.FullControl(rights)) edges.Add((c, sid, "GenericAll"));
                    if ((rights & ActiveDirectoryRights.WriteDacl) != 0) edges.Add((c, sid, "WriteDacl"));
                    if ((rights & ActiveDirectoryRights.WriteOwner) != 0) edges.Add((c, sid, "WriteOwner"));
                    if ((rights & ActiveDirectoryRights.ExtendedRight) != 0)
                    {
                        if (ot == Guid.Empty) edges.Add((c, sid, "AllExtendedRights"));
                        else if (ot == ForceChangePwd) edges.Add((c, sid, "ForceChangePassword"));
                    }
                    if (((rights & ActiveDirectoryRights.WriteProperty) != 0 || (rights & ActiveDirectoryRights.Self) != 0)
                        && isGroup && (ot == MemberAttr || ot == Guid.Empty))
                        edges.Add((c, sid, "AddMember"));
                    if ((rights & ActiveDirectoryRights.WriteProperty) != 0 && keyCred != null && ot == keyCred.Value)
                        edges.Add((c, sid, "AddKeyCredentialLink"));
                }
            }

            // ---- membership edges (member -> group) ----
            foreach (var g in groupMembers)
                foreach (var dn in g.memberDns)
                    if (dnToSid.TryGetValue(dn, out var msid))
                        edges.Add((msid, g.groupSid, "MemberOf"));

            // ---- delegation edges ----
            foreach (var cd in constrained)
                foreach (var spn in cd.spns)
                {
                    string host = SpnHost(spn);
                    if (host != null && hostToSid.TryGetValue(host, out var hsid))
                        edges.Add((cd.sid, hsid, "AllowedToDelegate"));
                }
            foreach (var u in unconstrained)
                if (!string.IsNullOrEmpty(domSid)) edges.Add((u, domSid, "Unconstrained"));

            // ---- session / local-admin edges (RPC, best-effort) ----
            RpcCollector.Collect(ctx, computers, nameOf, edges);

            // ---- DCSync edges on the domain head ----
            try
            {
                using (var dom = ctx.Bind(baseDn))
                {
                    dom.Options.SecurityMasks = SecurityMasks.Dacl;
                    var acc = new Dictionary<string, (bool gc, bool ga, bool all)>();
                    foreach (ActiveDirectoryAccessRule rule in dom.ObjectSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    {
                        if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                        string c = rule.IdentityReference.Value;
                        if (defaults.Contains(c)) continue;
                        bool genAll = CheckUtil.FullControl(rule.ActiveDirectoryRights);
                        bool ext = (rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) != 0;
                        bool gc = ext && (rule.ObjectType == GetChanges || rule.ObjectType == Guid.Empty);
                        bool ga = ext && (rule.ObjectType == GetChangesAll || rule.ObjectType == Guid.Empty);
                        acc.TryGetValue(c, out var cur);
                        acc[c] = (cur.gc || gc, cur.ga || ga, cur.all || genAll);
                    }
                    foreach (var kv in acc)
                        if (kv.Value.all || (kv.Value.gc && kv.Value.ga))
                            edges.Add((kv.Key, domSid, "DCSync"));
                }
            }
            catch (Exception ex) { ctx.Log?.Invoke("    [!] domain DACL read failed: " + ex.Message); }

            nameOf[domSid] = "DOMAIN(" + ctx.DomainDns + ")";

            // ---- fold in non-ACL vectors (Kerberoast / AS-REP / ADCS-ESC1) ----
            nameOf["S-1-5-11"] = "Authenticated Users";
            foreach (var ve in ctx.VectorEdges)
                edges.Add((ve.From, ve.To, ve.Type));

            // ---- target tier-0 set ----
            // Core admin groups: membership here means a legitimate admin, so members are
            // excluded as attack sources (tier0Members below uses only this list).
            var targetGroups = new List<string>();
            foreach (var rid in new[] { "-512", "-519", "-518", "-516", "-526", "-527" })
                if (!string.IsNullOrEmpty(domSid)) targetGroups.Add(domSid + rid);
            targetGroups.Add("S-1-5-32-544");

            var targets = new HashSet<string>(targetGroups, StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrEmpty(domSid)) { targets.Add(domSid + "-502"); targets.Add(domSid); }

            // High-value targets where MEMBERSHIP or CONTROL is itself DC compromise
            // (BloodHound-style). These are NOT added to targetGroups, so their members
            // still count as attack sources (membership here is the finding we want).
            foreach (var sid in new[] { "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551" })
                targets.Add(sid); // Account / Server / Print / Backup Operators
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectClass=group)(sAMAccountName=DnsAdmins))", "objectSid")))
            { var b = CheckUtil.Bytes(r, "objectSid"); if (b != null) targets.Add(new SecurityIdentifier(b, 0).Value); }
            foreach (var r in CheckUtil.Enumerate(ctx.SubtreeSearcher(baseDn,
                "(&(objectCategory=computer)" + LdapBit.HasFlag("userAccountControl", 8192) + ")", "objectSid")))
            { var b = CheckUtil.Bytes(r, "objectSid"); if (b != null) targets.Add(new SecurityIdentifier(b, 0).Value); }

            foreach (var t in targets) if (!nameOf.ContainsKey(t)) nameOf[t] = CheckUtil.TranslateSid(t);

            // ---- legitimate tier-0 members (excluded from "attack" sources) ----
            var childMap = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in edges)
                if (e.type == "MemberOf")
                {
                    if (!childMap.TryGetValue(e.to, out var l)) { l = new List<string>(); childMap[e.to] = l; }
                    l.Add(e.from);
                }
            var tier0Members = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var mq = new Queue<string>();
            foreach (var g in targetGroups) mq.Enqueue(g);
            while (mq.Count > 0)
            {
                var cur = mq.Dequeue();
                if (childMap.TryGetValue(cur, out var kids))
                    foreach (var k in kids)
                        if (tier0Members.Add(k)) mq.Enqueue(k);
            }

            // ---- reverse BFS from targets ----
            var reversed = new Dictionary<string, List<(string pred, string type)>>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in edges)
            {
                if (!reversed.TryGetValue(e.to, out var l)) { l = new List<(string, string)>(); reversed[e.to] = l; }
                l.Add((e.from, e.type));
            }
            var dist = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var nextHop = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var nextType = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var q = new Queue<string>();
            foreach (var t in targets) { dist[t] = 0; q.Enqueue(t); }
            while (q.Count > 0)
            {
                var cur = q.Dequeue();
                if (!reversed.TryGetValue(cur, out var preds)) continue;
                foreach (var (pred, type) in preds)
                {
                    if (dist.ContainsKey(pred)) continue;
                    dist[pred] = dist[cur] + 1;
                    nextHop[pred] = cur;
                    nextType[pred] = type;
                    q.Enqueue(pred);
                }
            }

            // ---- collect attack sources ----
            var sources = new List<string>();
            foreach (var kv in dist)
            {
                string node = kv.Key;
                if (targets.Contains(node) || tier0Members.Contains(node) || defaults.Contains(node)) continue;
                sources.Add(node);
            }
            sources.Sort((a, b) =>
            {
                int d = dist[a].CompareTo(dist[b]);
                return d != 0 ? d : string.Compare(Label(nameOf,a), Label(nameOf,b), StringComparison.OrdinalIgnoreCase);
            });

            var broad = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "S-1-5-11", "S-1-1-0", "S-1-5-7" };
            if (!string.IsNullOrEmpty(domSid)) { broad.Add(domSid + "-513"); broad.Add(domSid + "-515"); }

            var attack = new Finding("T3-AttackPaths", Category.PrivilegedAccounts, Severity.Critical, 30,
                "Privilege-escalation paths from non-admins to tier-0")
                .Why("Each path is a concrete chain of object-control rights that lets a non-privileged principal become domain admin.")
                .Fix("Break the weakest edge in each path (remove the dangerous ACL or membership).");
            var everyone = new Finding("T3-BroadToTier0", Category.PrivilegedAccounts, Severity.Critical, 35,
                "Broad principals can reach tier-0")
                .Why("A path from Authenticated Users / Domain Users / Everyone means effectively ANY user can escalate to domain admin.")
                .Fix("Eliminate the edge that exposes this path - highest priority.");

            foreach (var src in sources)
            {
                if (attack.Details.Count >= MaxPaths) break;
                CheckUtil.AddDetail(attack, "(" + dist[src] + " hops) " + BuildPath(src, targets, nextHop, nextType, nameOf));
            }
            foreach (var b in broad)
                if (dist.ContainsKey(b) && !targets.Contains(b))
                    CheckUtil.AddDetail(everyone, BuildPath(b, targets, nextHop, nextType, nameOf));

            // ---- build the full escalation subgraph (every shortest-path edge to tier-0) ----
            var sourceSet = new HashSet<string>(sources, StringComparer.OrdinalIgnoreCase);
            var graph = BuildGraph(edges, sourceSet, targets, broad, dist, nameOf);
            if (graph.Nodes.Count > 0) ctx.AttackGraph = graph;

            if (everyone.Details.Count > 0) yield return everyone;
            if (attack.Details.Count > 0) yield return attack;

            yield return new Finding("T3-GraphStats", Category.PrivilegedAccounts, Severity.Info, 0,
                "Control-graph statistics")
                .Why("Size of the analyzed control graph.")
                .Detail("nodes(named)=" + nameOf.Count + "  edges=" + edges.Count +
                        "  tier0-members=" + tier0Members.Count + "  escalation-sources=" + sources.Count);
        }

        private static string BuildPath(string src, HashSet<string> targets,
            Dictionary<string, string> nextHop, Dictionary<string, string> nextType, Dictionary<string, string> nameOf)
        {
            var sb = new System.Text.StringBuilder();
            string node = src;
            int hops = 0;
            while (!targets.Contains(node) && nextHop.ContainsKey(node) && hops++ < MaxHops)
            {
                sb.Append(Label(nameOf,node)).Append(" -[").Append(nextType[node]).Append("]-> ");
                node = nextHop[node];
            }
            sb.Append(Label(nameOf,node));
            return sb.ToString();
        }

        private const int MaxGraphEdges = 800;

        // Escalation subgraph = union of all shortest paths that START at a real entry
        // point (non-privileged source or broad principal). Forward-traversing from the
        // sources keeps legitimate admins (e.g. built-in Administrator) out of the graph,
        // while still drawing intermediate nodes that an attacker passes through.
        private static GraphModel BuildGraph(
            List<(string from, string to, string type)> edges,
            HashSet<string> sources, HashSet<string> targets, HashSet<string> broad,
            Dictionary<string, int> dist, Dictionary<string, string> nameOf)
        {
            // forward adjacency: any edge whose target can still reach tier-0
            var adj = new Dictionary<string, List<(string to, string type)>>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in edges)
            {
                if (!dist.ContainsKey(e.to)) continue; // 'to' must be able to reach tier-0
                if (!adj.TryGetValue(e.from, out var l)) { l = new List<(string, string)>(); adj[e.from] = l; }
                l.Add((e.to, e.type));
            }

            var starts = new HashSet<string>(sources, StringComparer.OrdinalIgnoreCase);
            foreach (var b in broad)
                if (dist.ContainsKey(b) && !targets.Contains(b)) starts.Add(b);

            var g = new GraphModel();
            var pair = new Dictionary<string, GraphEdge>(StringComparer.OrdinalIgnoreCase);
            var visited = new HashSet<string>(starts, StringComparer.OrdinalIgnoreCase);
            var q = new Queue<string>(starts);
            while (q.Count > 0)
            {
                var cur = q.Dequeue();
                if (targets.Contains(cur)) continue;        // do not expand out of tier-0 targets
                if (!adj.TryGetValue(cur, out var outs)) continue;
                foreach (var (to, type) in outs)
                {
                    string key = cur + "|" + to;
                    if (!pair.TryGetValue(key, out var ge))
                    {
                        if (g.Edges.Count >= MaxGraphEdges) continue;
                        ge = new GraphEdge { From = cur, To = to, Type = type };
                        pair[key] = ge;
                        g.Edges.Add(ge);
                    }
                    else if (Priority(type) > Priority(ge.Type)) ge.Type = type;
                    if (visited.Add(to)) q.Enqueue(to);
                }
            }

            // mark control edges that step directly into tier-0 as the break point
            foreach (var ge in g.Edges)
                if (ge.Type != "MemberOf" && dist.TryGetValue(ge.To, out var d0) && d0 == 0)
                    ge.Weak = true;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var ge in g.Edges)
            {
                AddNode(g, seen, ge.From, targets, broad, starts, dist, nameOf);
                AddNode(g, seen, ge.To, targets, broad, starts, dist, nameOf);
            }
            return g;
        }

        // Preference order when collapsing parallel edges to a single label.
        private static int Priority(string t)
        {
            switch (t)
            {
                case "GenericAll": return 100;
                case "WriteDacl": return 90;
                case "WriteOwner": return 85;
                case "Owns": return 80;
                case "AllExtendedRights": return 75;
                case "AddKeyCredentialLink": return 70;
                case "ForceChangePassword": return 65;
                case "AddMember": return 60;
                case "DCSync": return 55;
                case "AllowedToAct": return 50;
                case "AllowedToDelegate": return 48;
                case "Unconstrained": return 46;
                case "ADCS-ESC1": return 44;
                case "Kerberoast": return 42;
                case "ASREPRoast": return 40;
                case "AdminTo": return 30;
                case "HasSession": return 28;
                case "MemberOf": return 10;
                default: return 1;
            }
        }

        private static void AddNode(GraphModel g, HashSet<string> seen, string sid, HashSet<string> targets,
            HashSet<string> broad, HashSet<string> starts, Dictionary<string, int> dist, Dictionary<string, string> nameOf)
        {
            if (!seen.Add(sid)) return;
            string kind = targets.Contains(sid) ? "target"
                        : broad.Contains(sid) ? "broad"
                        : starts.Contains(sid) ? "source" : "mid";
            g.Nodes.Add(new GraphNode
            {
                Id = sid,
                Label = Label(nameOf, sid),
                Kind = kind,
                Distance = dist.TryGetValue(sid, out var d) ? d : 0
            });
        }

        private static string Label(Dictionary<string, string> nameOf, string sid)
            => nameOf.TryGetValue(sid, out var n) ? n : CheckUtil.TranslateSid(sid);

        private static string ShortDn(string dn)
        {
            int i = dn.IndexOf(',');
            string head = i > 0 ? dn.Substring(0, i) : dn;
            return head.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? head.Substring(3) : head;
        }

        // Extract the host part of an SPN, e.g. "cifs/host.dom:445" -> "host.dom".
        private static string SpnHost(string spn)
        {
            if (string.IsNullOrEmpty(spn)) return null;
            int slash = spn.IndexOf('/');
            if (slash < 0) return null;
            string rest = spn.Substring(slash + 1);
            int cut = rest.IndexOfAny(new[] { ':', '/' });
            if (cut >= 0) rest = rest.Substring(0, cut);
            return rest.Length > 0 ? rest : null;
        }
    }
}
