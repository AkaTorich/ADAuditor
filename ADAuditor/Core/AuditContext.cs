using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Net;
using System.Reflection;
using System.Security.Principal;

namespace ADAuditor.Core
{
    // Holds the live LDAP binding plus naming contexts and shared helpers.
    public sealed class AuditContext : IDisposable
    {
        public string Server { get; private set; }            // DC host or domain DNS (may be null = auto)
        public NetworkCredential Credential { get; private set; }
        public Action<string> Log { get; set; }

        public string DefaultNamingContext { get; private set; }
        public string ConfigurationNamingContext { get; private set; }
        public string SchemaNamingContext { get; private set; }
        public string RootDomainNamingContext { get; private set; }
        public string DnsHostName { get; private set; }
        public string DomainDns { get; private set; }
        public string ForestDns { get; private set; }
        public int DomainFunctionality { get; private set; }
        public int ForestFunctionality { get; private set; }
        public SecurityIdentifier DomainSid { get; private set; }

        // Filled by the Tier 3 module for the graph visualization (optional).
        public GraphModel AttackGraph { get; set; }

        // Non-ACL escalation vectors (Kerberoast, AS-REP, ADCS-ESC1, ...) that earlier
        // modules contribute and Tier 3 folds into the attack-path graph as edges.
        public List<GraphEdge> VectorEdges { get; } = new List<GraphEdge>();

        private readonly AuthenticationTypes _auth;

        public AuditContext(string server, NetworkCredential credential)
        {
            Server = string.IsNullOrWhiteSpace(server) ? null : server.Trim();
            Credential = credential;
            _auth = AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.ServerBind;
        }

        private void W(string s) { Log?.Invoke(s); }

        // Build an LDAP://[server/]<dn> path
        public string Path(string dn)
        {
            if (Server != null)
                return "LDAP://" + Server + "/" + dn;
            return "LDAP://" + dn;
        }

        public DirectoryEntry Bind(string dn)
        {
            var path = Path(dn);
            if (Credential != null && !string.IsNullOrEmpty(Credential.UserName))
            {
                string user = string.IsNullOrEmpty(Credential.Domain)
                    ? Credential.UserName
                    : Credential.Domain + "\\" + Credential.UserName;
                return new DirectoryEntry(path, user, Credential.Password, _auth);
            }
            return new DirectoryEntry(path, null, null, _auth);
        }

        // Read RootDSE and resolve naming contexts. Throws on failure.
        public void Connect()
        {
            W("[*] Reading RootDSE ...");
            using (var root = Bind("RootDSE"))
            {
                DefaultNamingContext = Str(root, "defaultNamingContext");
                ConfigurationNamingContext = Str(root, "configurationNamingContext");
                SchemaNamingContext = Str(root, "schemaNamingContext");
                RootDomainNamingContext = Str(root, "rootDomainNamingContext");
                DnsHostName = Str(root, "dnsHostName");
                DomainFunctionality = ParseInt(Str(root, "domainFunctionality"));
                ForestFunctionality = ParseInt(Str(root, "forestFunctionality"));
            }
            if (string.IsNullOrEmpty(DefaultNamingContext))
                throw new InvalidOperationException("RootDSE did not return defaultNamingContext - check server/credentials.");

            DomainDns = DnFromDc(DefaultNamingContext);
            ForestDns = DnFromDc(RootDomainNamingContext);
            W("[+] Bound to domain " + DomainDns + " (" + DefaultNamingContext + ")");

            // domain SID lives on the domain head object
            using (var dom = Bind(DefaultNamingContext))
            {
                var sidBytes = dom.Properties["objectSid"].Value as byte[];
                if (sidBytes != null) DomainSid = new SecurityIdentifier(sidBytes, 0);
            }
        }

        // Convert "DC=corp,DC=local" -> "corp.local"
        public static string DnFromDc(string dn)
        {
            if (string.IsNullOrEmpty(dn)) return "";
            var parts = new List<string>();
            foreach (var seg in dn.Split(','))
            {
                var t = seg.Trim();
                if (t.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    parts.Add(t.Substring(3));
            }
            return string.Join(".", parts);
        }

        // Configured searcher with sensible paging defaults
        public DirectorySearcher Searcher(string baseDn, string filter, SearchScope scope, params string[] attrs)
        {
            var entry = Bind(baseDn);
            var s = new DirectorySearcher(entry)
            {
                Filter = filter,
                SearchScope = scope,
                PageSize = 1000,
                SizeLimit = 0,
                ReferralChasing = ReferralChasingOption.None
            };
            if (attrs != null)
                foreach (var a in attrs) s.PropertiesToLoad.Add(a);
            return s;
        }

        public DirectorySearcher SubtreeSearcher(string baseDn, string filter, params string[] attrs)
            => Searcher(baseDn, filter, SearchScope.Subtree, attrs);

        // ---- value helpers ----

        public static string Str(DirectoryEntry e, string prop)
        {
            var v = e.Properties[prop].Value;
            return v?.ToString() ?? "";
        }

        public static string Str(System.DirectoryServices.SearchResult r, string prop)
        {
            if (r.Properties.Contains(prop) && r.Properties[prop].Count > 0)
                return r.Properties[prop][0]?.ToString() ?? "";
            return "";
        }

        public static int ParseInt(string s)
        {
            return int.TryParse(s, out var i) ? i : 0;
        }

        // Large integer (FILETIME / int64 stored attributes) -> long
        public static long ToInt64(object val)
        {
            if (val == null) return 0;
            if (val is long l) return l;
            if (val is int i) return i;
            // IADsLargeInteger COM object exposes HighPart / LowPart
            var t = val.GetType();
            try
            {
                int high = (int)t.InvokeMember("HighPart", BindingFlags.GetProperty, null, val, null);
                int low = (int)t.InvokeMember("LowPart", BindingFlags.GetProperty, null, val, null);
                return ((long)high << 32) | (uint)low;
            }
            catch
            {
                return long.TryParse(val.ToString(), out var p) ? p : 0;
            }
        }

        public static long Int64Of(System.DirectoryServices.SearchResult r, string prop)
        {
            if (r.Properties.Contains(prop) && r.Properties[prop].Count > 0)
                return ToInt64(r.Properties[prop][0]);
            return 0;
        }

        // FILETIME (100ns ticks since 1601) -> DateTime?, null if 0 or "never"
        public static DateTime? FileTime(long ft)
        {
            if (ft <= 0 || ft == long.MaxValue) return null;
            try { return DateTime.FromFileTimeUtc(ft); }
            catch { return null; }
        }

        public void Dispose() { }
    }
}
