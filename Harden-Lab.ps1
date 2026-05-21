<#
    Harden-Lab.ps1
    Remediates the findings produced by AD_AUDITOR on the lab domain.

    TARGET: LAB.LOCAL (NetBIOS LAB), domain controller DC01.
    RUN ON the domain controller, as a Domain Admin, in an elevated PowerShell.

    It applies baseline hardening (password policy, machine-account quota,
    AD Recycle Bin, admin protection) and surgically removes the dangerous
    ACEs / SPNs that Seed-LabVulns.ps1 created, without touching default rights.

    WARNING: for an isolated LAB only. Review before running in production.
#>

[CmdletBinding()]
param([string]$NetBios = "LAB")

Import-Module ActiveDirectory -ErrorAction Stop

$domain = (Get-ADDomain)
$dn     = $domain.DistinguishedName
$root   = $domain.DNSRoot
$domSid = $domain.DomainSID.Value
$cfg    = (Get-ADRootDSE).configurationNamingContext

function Step($msg, [scriptblock]$action) {
    try { & $action; Write-Host ("[+] " + $msg) -ForegroundColor Green }
    catch { Write-Host ("[!] " + $msg + " -> " + $_.Exception.Message) -ForegroundColor Yellow }
}
function Note($msg) { Write-Host ("[i] " + $msg) -ForegroundColor DarkGray }

# Remove ONE specific allow ACE (mirror of the seed) without disturbing others.
function Remove-Ace($objectDn, $sid, $right, $guid) {
    $path  = "AD:\$objectDn"
    $acl   = Get-Acl $path
    $adr   = [System.DirectoryServices.ActiveDirectoryRights]$right
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    if ($guid) {
        $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid, $adr, $allow, [guid]$guid)
    } else {
        $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid, $adr, $allow)
    }
    [void]$acl.RemoveAccessRuleSpecific($rule)
    Set-Acl $path $acl
}

$G_GetChanges    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$G_GetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
$G_ForcePwd      = "00299570-246d-11d0-a768-00aa006e0529"
$keyCredGuid = (Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
    -Filter "lDAPDisplayName -eq 'msDS-KeyCredentialLink'" -Properties schemaIDGUID -ErrorAction SilentlyContinue).schemaIDGUID
if ($keyCredGuid) { $keyCredGuid = ([guid]$keyCredGuid).ToString() }

Write-Host "=== HARDENING $dn ===" -ForegroundColor Cyan

# ---- Domain-wide baseline ----
Step "A-PasswordPolicy + A-DomainReversible: strong default password policy" {
    Set-ADDefaultDomainPasswordPolicy -Identity $root `
        -MinPasswordLength 14 -ComplexityEnabled $true -PasswordHistoryCount 24 `
        -LockoutThreshold 10 -LockoutDuration (New-TimeSpan -Minutes 15) `
        -LockoutObservationWindow (New-TimeSpan -Minutes 15) `
        -ReversibleEncryptionEnabled $false
}
Step "A-MachineAccountQuota: set quota to 0" {
    Set-ADDomain -Identity $root -Replace @{"ms-DS-MachineAccountQuota"="0"}
}
Step "A-RecycleBin: enable AD Recycle Bin (irreversible)" {
    Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet `
        -Target (Get-ADForest).Name -Confirm:$false
}
Step "A-AnonymousLdap: reset dSHeuristics" {
    Set-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$cfg" -Replace @{dSHeuristics='0'} -ErrorAction SilentlyContinue
}

# ---- Account hygiene ----
Step "S-PwdNeverExpires: clear 'password never expires' on enabled users" {
    Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } |
        ForEach-Object { Set-ADUser $_ -PasswordNeverExpires $false }
}
Step "S-*: clear weak flags on victim" {
    if (Get-ADUser -Filter "sAMAccountName -eq 'victim'") {
        Set-ADAccountControl victim -AllowReversiblePasswordEncryption $false -UseDESKeyOnly $false -PasswordNotRequired $false
        Set-ADUser victim -AccountExpirationDate $null -Clear 'msDS-SupportedEncryptionTypes','description' -ErrorAction SilentlyContinue
    }
}
Step "P-AdminsDelegatable: mark Administrator/krbtgt as not-delegated" {
    Set-ADAccountControl Administrator -AccountNotDelegated $true
    Set-ADAccountControl krbtgt -AccountNotDelegated $true
}
Step "P-GuestEnabled: disable Guest" { Disable-ADAccount Guest }
Step "P-DnsAdmins / P-BroadInPriv: empty dangerous group memberships" {
    Remove-ADGroupMember "DnsAdmins" testuser -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ADGroupMember "Backup Operators" "Domain Users" -Confirm:$false -ErrorAction SilentlyContinue
}
Step "A-PreWin2000: remove Anonymous Logon from Pre-Windows 2000 group" {
    Remove-ADGroupMember "Pre-Windows 2000 Compatible Access" -Members "S-1-5-7" -Confirm:$false -ErrorAction SilentlyContinue
}

# ---- Kerberos ----
Step "A-Kerberoast / P-PrivKerberoast: remove SPNs from user accounts" {
    foreach ($u in "svc1","da1") {
        $o = Get-ADUser -Filter "sAMAccountName -eq '$u'" -Properties servicePrincipalName -ErrorAction SilentlyContinue
        if ($o -and $o.servicePrincipalName) { Set-ADUser $o -ServicePrincipalNames @{Replace=@()} }
    }
    Remove-ADGroupMember "Domain Admins" da1 -Confirm:$false -ErrorAction SilentlyContinue
}
Step "A-AsrepRoast: re-enable Kerberos pre-auth" {
    foreach ($u in "svc1","da1") {
        if (Get-ADUser -Filter "sAMAccountName -eq '$u'") { Set-ADAccountControl $u -DoesNotRequirePreAuth $false }
    }
}
Step "A-Unconstrained / A-Constrained / A-RBCD: clear delegation on OLDBOX/svc1" {
    if (Get-ADComputer -Filter "Name -eq 'OLDBOX'") {
        Set-ADAccountControl OLDBOX -TrustedForDelegation $false
        Set-ADComputer OLDBOX -PrincipalsAllowedToDelegateToAccount $null
    }
    if (Get-ADUser -Filter "sAMAccountName -eq 'svc1'") { Set-ADUser svc1 -Clear 'msDS-AllowedToDelegateTo' -ErrorAction SilentlyContinue }
}

# ---- ACL control edges (closes X-Acl* and T3-AttackPaths) ----
$tu = (Get-ADUser -Filter "sAMAccountName -eq 'testuser'" -ErrorAction SilentlyContinue).SID
if ($tu) {
    Step "X-AclGenericAll/WriteDacl/WriteMember/AllExtended + T3: revoke GenericAll on Domain Admins" {
        Remove-Ace "CN=Domain Admins,CN=Users,$dn" $tu "GenericAll" $null
    }
    Step "X-DCSync: revoke replication rights on the domain head" {
        Remove-Ace $dn $tu "ExtendedRight" $G_GetChanges
        Remove-Ace $dn $tu "ExtendedRight" $G_GetChangesAll
    }
    Step "X-AclForceChangePwd / X-ShadowCredWrite: revoke on victim" {
        $vdn = (Get-ADUser victim -ErrorAction SilentlyContinue).DistinguishedName
        if ($vdn) {
            Remove-Ace $vdn $tu "ExtendedRight" $G_ForcePwd
            if ($keyCredGuid) { Remove-Ace $vdn $tu "WriteProperty" $keyCredGuid }
        }
    }
}

# ---- AD CS ----
Step "C-ESC4: revoke Domain Users write on the User template" {
    $tpl = "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
    if (Get-ADObject -Identity $tpl -ErrorAction SilentlyContinue) {
        Remove-Ace $tpl ((Get-ADGroup "Domain Users").SID) "WriteProperty" $null
    }
}
Step "C-ESC13: remove issuance-policy to group links" {
    Get-ADObject -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$cfg" `
        -Filter "objectClass -eq 'msPKI-Enterprise-Oid'" -Properties msDS-OIDToGroupLink -ErrorAction SilentlyContinue |
        Where-Object { $_.'msDS-OIDToGroupLink' } |
        ForEach-Object { Set-ADObject $_ -Clear 'msDS-OIDToGroupLink' }
}
Step "C-ESC1 / C-ESC15: require manager approval on enrollee-supplied-subject templates open to low-priv users" {
    $tplBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
    $lowSids = @("S-1-5-11", "$domSid-513")  # Authenticated Users, Domain Users
    Get-ADObject -SearchBase $tplBase -Filter "objectClass -eq 'pKICertificateTemplate'" `
        -Properties 'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','cn' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $supplies = ($_.'msPKI-Certificate-Name-Flag' -band 0x1) -ne 0
        if (-not $supplies) { return }
        $acl = Get-Acl ("AD:\" + $_.DistinguishedName)
        $lowEnroll = $false
        foreach ($r in $acl.Access) {
            try { $rs = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $rs = $r.IdentityReference.Value }
            if (($lowSids -contains $rs) -and ($r.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) { $lowEnroll = $true }
        }
        if ($lowEnroll) {
            $flag = [int]$_.'msPKI-Enrollment-Flag' -bor 0x2   # CT_FLAG_PEND_ALL_REQUESTS (manager approval)
            Set-ADObject $_ -Replace @{ 'msPKI-Enrollment-Flag' = $flag }
            Note ("required manager approval on template " + $_.cn)
        }
    }
}

# ---- ADIDNS ----
Step "E-Adidns: remove 'Authenticated Users : Create child' on AD-integrated zones" {
    $au = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-11"
    foreach ($part in @("DC=DomainDnsZones,$dn", "CN=MicrosoftDNS,CN=System,$dn")) {
        Get-ADObject -SearchBase $part -Filter "objectClass -eq 'dnsZone'" -ErrorAction SilentlyContinue | ForEach-Object {
            $p = "AD:\" + $_.DistinguishedName
            $acl = Get-Acl $p
            $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($au, [System.DirectoryServices.ActiveDirectoryRights]::CreateChild, [System.Security.AccessControl.AccessControlType]::Allow)
            [void]$acl.RemoveAccessRuleSpecific($rule)
            Set-Acl $p $acl
        }
    }
}

# ---- E-NoAuthSilo ----
Step "E-NoAuthSilo: create a tier-0 authentication policy silo" {
    if (-not (Get-ADAuthenticationPolicySilo -Filter "Name -eq 'Tier0-Silo'" -ErrorAction SilentlyContinue)) {
        New-ADAuthenticationPolicy     -Name "Tier0-Policy" -Enforce -ErrorAction SilentlyContinue
        New-ADAuthenticationPolicySilo -Name "Tier0-Silo" -Enforce -ErrorAction SilentlyContinue
    }
    Note "Assign tier-0 accounts to the silo and add them to Protected Users to complete this control."
}

Write-Host ""
Write-Host "=== MANUAL / BY-DESIGN (not auto-fixed) ===" -ForegroundColor Cyan
Note "A-NoLAPS         : deploy Windows LAPS (GPO + schema), then re-run."
Note "C-ESC5           : review/remove non-default control ACEs on CA and PKI containers manually."
Note "P-DomainAdmins/EnterpriseAdmins/SchemaAdmins/Administrators = 1 : this is the built-in Administrator - expected baseline, not a defect."
Note "P-AccountOperators..PrintOperators = 0 : already empty (good)."
Note "P-AdminCount = 2 / P-EmptyPrivGroups : Administrator+krbtgt and default protected groups - by design."
Note "SYSVOL GPP cpassword / Restricted Groups / Kerberos ticket lifetimes : remediate via Group Policy."

Write-Host ""
Write-Host "=== DONE. Re-run AD_AUDITOR to confirm the findings are cleared. ===" -ForegroundColor Cyan
