using System;

namespace ADAuditor.Core
{
    // userAccountControl bit flags (msDS-User-Account-Control-Computed shares some)
    [Flags]
    public enum Uac : long
    {
        Script = 0x0001,
        AccountDisabled = 0x0002,
        HomedirRequired = 0x0008,
        Lockout = 0x0010,
        PasswdNotReqd = 0x0020,
        PasswdCantChange = 0x0040,
        EncryptedTextPwdAllowed = 0x0080,   // reversible encryption
        TempDuplicateAccount = 0x0100,
        NormalAccount = 0x0200,
        InterdomainTrustAccount = 0x0800,
        WorkstationTrustAccount = 0x1000,
        ServerTrustAccount = 0x2000,        // domain controller computer object
        DontExpirePassword = 0x10000,
        MnsLogonAccount = 0x20000,
        SmartcardRequired = 0x40000,
        TrustedForDelegation = 0x80000,     // unconstrained delegation
        NotDelegated = 0x100000,
        UseDesKeyOnly = 0x200000,
        DontRequirePreauth = 0x400000,      // AS-REP roastable
        PasswordExpired = 0x800000,
        TrustedToAuthForDelegation = 0x1000000 // constrained delegation w/ protocol transition
    }

    // OID for LDAP_MATCHING_RULE_BIT_AND used in bitwise filters
    public static class LdapBit
    {
        public const string And = "1.2.840.113556.1.4.803";
        public const string Or = "1.2.840.113556.1.4.804";

        public static string HasFlag(string attr, long flag)
        {
            return "(" + attr + ":" + And + ":=" + flag + ")";
        }
    }

    // trustAttributes bits (on trustedDomain objects)
    [Flags]
    public enum TrustAttributes
    {
        NonTransitive = 0x1,
        UplevelOnly = 0x2,
        QuarantinedDomain = 0x4,        // SID filtering enabled
        ForestTransitive = 0x8,
        CrossOrganization = 0x10,
        WithinForest = 0x20,
        TreatAsExternal = 0x40,
        UsesRc4Encryption = 0x80,
        CrossOrgNoTgtDelegation = 0x200,
        PimTrust = 0x400
    }

    // pwdProperties bits on the domain object
    [Flags]
    public enum PwdProperties
    {
        Complex = 0x1,
        NoAnonChange = 0x2,
        NoClearChange = 0x4,
        LockoutAdmins = 0x8,
        StoreCleartext = 0x10,          // reversible encryption domain-wide
        RefuseChangeLater = 0x20
    }
}
