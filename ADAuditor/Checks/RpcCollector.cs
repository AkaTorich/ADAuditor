using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    // Best-effort RPC collection of lateral-movement edges for the Tier 3 graph:
    //   AdminTo    : a principal is a local administrator on a computer
    //   HasSession : a user has a logon session on a computer
    // Uses standard Win32 (netapi32/advapi32) over RPC, read-only, current session
    // credentials. Local-admin enumeration usually requires admin on the target,
    // so unreachable hosts are simply skipped.
    internal static class RpcCollector
    {
        private const int MaxHosts = 150;
        private const int Parallelism = 12;
        private const int MAX_PREFERRED_LENGTH = -1;

        public static void Collect(AuditContext ctx, List<(string sid, string host)> computers,
            Dictionary<string, string> nameOf, List<(string from, string to, string type)> edges)
        {
            if (computers == null || computers.Count == 0) return;

            // sAMAccountName (lower) -> SID, to resolve session usernames
            var samToSid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in nameOf)
                if (!samToSid.ContainsKey(kv.Value)) samToSid[kv.Value] = kv.Key;

            var hosts = computers;
            if (hosts.Count > MaxHosts) hosts = hosts.GetRange(0, MaxHosts);
            ctx.Log?.Invoke("    [*] RPC session/local-admin sweep over " + hosts.Count + " hosts (best-effort) ...");

            var found = new ConcurrentBag<(string from, string to, string type)>();
            int reached = 0;

            Parallel.ForEach(hosts, new ParallelOptions { MaxDegreeOfParallelism = Parallelism }, c =>
            {
                bool ok = false;

                // local administrators -> AdminTo
                foreach (var memberSid in LocalAdmins(c.host))
                {
                    ok = true;
                    if (nameOf.ContainsKey(memberSid))
                        found.Add((memberSid, c.sid, "AdminTo"));
                }

                // logon sessions -> HasSession
                foreach (var user in LoggedOnUsers(c.host))
                {
                    ok = true;
                    if (samToSid.TryGetValue(user, out var usid) && usid != c.sid)
                        found.Add((c.sid, usid, "HasSession"));
                }

                if (ok) System.Threading.Interlocked.Increment(ref reached);
            });

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in found)
                if (seen.Add(e.from + "|" + e.to + "|" + e.type))
                    edges.Add(e);

            ctx.Log?.Invoke("    [+] RPC sweep: " + reached + "/" + hosts.Count + " hosts responded, " +
                            edges.Count + " lateral edges (cumulative).");
        }

        private static IEnumerable<string> LocalAdmins(string host)
        {
            var result = new List<string>();
            string group = AdminGroupName(host);
            IntPtr buf = IntPtr.Zero;
            try
            {
                int rc = NetLocalGroupGetMembers(host, group, 2, out buf, MAX_PREFERRED_LENGTH,
                    out int read, out int total, IntPtr.Zero);
                if (rc != 0 || buf == IntPtr.Zero) return result;
                IntPtr cur = buf;
                int sz = Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2));
                for (int i = 0; i < read; i++)
                {
                    var item = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(cur, typeof(LOCALGROUP_MEMBERS_INFO_2));
                    if (item.lgrmi2_sid != IntPtr.Zero)
                    {
                        try { result.Add(new SecurityIdentifier(item.lgrmi2_sid).Value); } catch { }
                    }
                    cur = IntPtr.Add(cur, sz);
                }
            }
            catch { }
            finally { if (buf != IntPtr.Zero) NetApiBufferFree(buf); }
            return result;
        }

        private static IEnumerable<string> LoggedOnUsers(string host)
        {
            var result = new List<string>();
            IntPtr buf = IntPtr.Zero;
            try
            {
                int rc = NetWkstaUserEnum(host, 1, out buf, MAX_PREFERRED_LENGTH,
                    out int read, out int total, IntPtr.Zero);
                if (rc != 0 || buf == IntPtr.Zero) return result;
                IntPtr cur = buf;
                int sz = Marshal.SizeOf(typeof(WKSTA_USER_INFO_1));
                for (int i = 0; i < read; i++)
                {
                    var item = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(cur, typeof(WKSTA_USER_INFO_1));
                    if (!string.IsNullOrEmpty(item.wkui1_username) && !item.wkui1_username.EndsWith("$"))
                        result.Add(item.wkui1_username);
                    cur = IntPtr.Add(cur, sz);
                }
            }
            catch { }
            finally { if (buf != IntPtr.Zero) NetApiBufferFree(buf); }
            return result;
        }

        // Localized name of the built-in Administrators group (S-1-5-32-544) on the host.
        private static string AdminGroupName(string host)
        {
            try
            {
                var sid = new SecurityIdentifier("S-1-5-32-544");
                var bytes = new byte[sid.BinaryLength];
                sid.GetBinaryForm(bytes, 0);
                var name = new StringBuilder(256);
                int cch = name.Capacity;
                var dom = new StringBuilder(256);
                int cchd = dom.Capacity;
                if (LookupAccountSid(host, bytes, name, ref cch, dom, ref cchd, out _))
                    return name.ToString();
            }
            catch { }
            return "Administrators";
        }

        // ---- P/Invoke ----

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetLocalGroupGetMembers(string servername, string localgroupname, int level,
            out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, IntPtr resumehandle);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetWkstaUserEnum(string servername, int level, out IntPtr bufptr,
            int prefmaxlen, out int entriesread, out int totalentries, IntPtr resumehandle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupAccountSid(string systemName, byte[] sid, StringBuilder name,
            ref int cchName, StringBuilder referencedDomainName, ref int cchReferencedDomainName, out int use);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LOCALGROUP_MEMBERS_INFO_2
        {
            public IntPtr lgrmi2_sid;
            public int lgrmi2_sidusage;
            public IntPtr lgrmi2_domainandname;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WKSTA_USER_INFO_1
        {
            public string wkui1_username;
            public string wkui1_logon_domain;
            public string wkui1_oth_domains;
            public string wkui1_logon_server;
        }
    }
}
