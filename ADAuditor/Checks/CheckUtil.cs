using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using ADAuditor.Core;

namespace ADAuditor.Checks
{
    internal static class CheckUtil
    {
        public const int MaxDetails = 60; // cap per-finding detail rows

        // Enumerate search results safely (disposes searcher + entry).
        public static IEnumerable<SearchResult> Enumerate(DirectorySearcher searcher)
        {
            using (searcher)
            using (var results = searcher.FindAll())
            {
                foreach (SearchResult r in results)
                    yield return r;
            }
        }

        public static void AddDetail(Finding f, string line)
        {
            if (f.Details.Count < MaxDetails)
                f.Detail(line);
            else if (f.Details.Count == MaxDetails)
                f.Detail("... (list truncated)");
        }

        // Whole days elapsed since a FILETIME; -1 if unset / never.
        public static int DaysSince(long filetime)
        {
            var dt = AuditContext.FileTime(filetime);
            if (dt == null) return -1;
            return (int)(DateTime.UtcNow - dt.Value).TotalDays;
        }

        public static string FmtDate(long filetime)
        {
            var dt = AuditContext.FileTime(filetime);
            return dt == null ? "never" : dt.Value.ToString("yyyy-MM-dd");
        }

        // Convert a negative 100ns interval attribute (maxPwdAge etc.) to days.
        public static double IntervalToDays(long raw)
        {
            if (raw == 0 || raw == long.MinValue) return 0;
            return Math.Abs(raw) / 864000000000.0;
        }

        public static string Sam(SearchResult r) => AuditContext.Str(r, "sAMAccountName");
        public static string Dn(SearchResult r) => AuditContext.Str(r, "distinguishedName");

        public static bool HasClass(SearchResult r, string cls)
        {
            if (!r.Properties.Contains("objectClass")) return false;
            foreach (var v in r.Properties["objectClass"])
                if (string.Equals(v?.ToString(), cls, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public static byte[] Bytes(SearchResult r, string prop)
        {
            if (r.Properties.Contains(prop) && r.Properties[prop].Count > 0)
                return r.Properties[prop][0] as byte[];
            return null;
        }

        // Resolve SID -> readable account name; fall back to the SID string.
        public static string TranslateSid(string sid)
        {
            try { return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
            catch { return sid; }
        }

        // Build an ActiveDirectorySecurity from a raw nTSecurityDescriptor blob.
        public static ActiveDirectorySecurity ParseSd(byte[] blob)
        {
            var sd = new ActiveDirectorySecurity();
            sd.SetSecurityDescriptorBinaryForm(blob, AccessControlSections.Owner | AccessControlSections.Access);
            return sd;
        }

        // Look up an attribute's schemaIDGUID (environment-specific for LAPS/KeyCredentialLink).
        public static Guid? SchemaGuid(AuditContext ctx, string ldapName)
        {
            foreach (var r in Enumerate(ctx.SubtreeSearcher(ctx.SchemaNamingContext,
                "(&(objectClass=attributeSchema)(lDAPDisplayName=" + ldapName + "))", "schemaIDGUID")))
            {
                var b = Bytes(r, "schemaIDGUID");
                if (b != null && b.Length == 16) return new Guid(b);
            }
            return null;
        }

        // Principals whose control over objects is expected/by-design; excluded to cut noise.
        public static HashSet<string> DefaultPrivSids(string domSid)
        {
            var s = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "S-1-5-18",      // LocalSystem
                "S-1-5-19",      // LocalService
                "S-1-5-20",      // NetworkService
                "S-1-5-10",      // Self / Principal Self
                "S-1-3-0",       // Creator Owner
                "S-1-5-9",       // Enterprise Domain Controllers
                "S-1-5-32-544",  // BUILTIN\Administrators
                "S-1-5-32-548",  // Account Operators (broad by design)
                "S-1-5-32-549",  // Server Operators
                "S-1-5-32-550",  // Print Operators
                "S-1-5-32-551",  // Backup Operators
                "S-1-5-32-554",  // Pre-Windows 2000 Compatible Access
                "S-1-5-32-557",  // Incoming Forest Trust Builders
                "S-1-5-32-560",  // Windows Authorization Access Group
                "S-1-5-32-561",  // Terminal Server License Servers
                "S-1-5-32-562",  // Distributed COM Users
                "S-1-5-32-568"   // IIS_IUSRS
            };
            if (!string.IsNullOrEmpty(domSid))
            {
                // RID-based built-ins that hold default delegations on a clean domain
                foreach (var rid in new[]
                {
                    "-500", // Administrator
                    "-502", // krbtgt
                    "-512", // Domain Admins
                    "-516", // Domain Controllers
                    "-517", // Cert Publishers
                    "-518", // Schema Admins
                    "-519", // Enterprise Admins
                    "-520", // Group Policy Creator Owners
                    "-521", // Read-only Domain Controllers
                    "-498", // Enterprise Read-only Domain Controllers
                    "-526", // Key Admins
                    "-527", // Enterprise Key Admins
                    "-553", // RAS and IAS Servers
                    "-571", // Allowed RODC Password Replication Group
                    "-572"  // Denied RODC Password Replication Group
                })
                    s.Add(domSid + rid);
            }
            return s;
        }

        // True only for a real Full Control ACE. ActiveDirectoryRights.GenericAll is a
        // composite mask (0xF01FF incl. ReadControl/ReadProperty), so "& GenericAll != 0"
        // would match ordinary read ACEs; require ALL the bits to be present.
        public static bool FullControl(ActiveDirectoryRights r)
            => (r & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll;

        // Set the searcher up to return security descriptors (DACL + owner).
        public static DirectorySearcher WithDacl(DirectorySearcher s)
        {
            s.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;
            return s;
        }

        // DNS host names of all writable + read-only domain controllers.
        public static List<string> DomainControllers(AuditContext ctx)
        {
            var list = new List<string>();
            foreach (var r in Enumerate(ctx.SubtreeSearcher(ctx.DefaultNamingContext,
                "(&(objectCategory=computer)" + LdapBit.HasFlag("userAccountControl", 8192) + ")", "dNSHostName")))
            {
                string h = AuditContext.Str(r, "dNSHostName");
                if (!string.IsNullOrEmpty(h)) list.Add(h);
            }
            return list;
        }
    }
}
