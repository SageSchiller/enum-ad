<#
    enum-ad.ps1 - Active Directory enumeration via .NET + ADSI

    Pure LDAP enumeration that needs only a basic domain user and no RSAT / no
    installed modules. Run it on any domain-joined Windows host.

    ============================ FEATURE REFERENCE ============================
    What each option is for (the "why", so you remember when to reach for it):

      -Users         List every user account.            Build a spray/userlist.
      -Groups        List every group.                   Spot custom/odd groups to dig into.
      -Computers     List computers + OS.                Find servers, old OSes, targets.
      -Descriptions  Objects with a description set.      Admins hide passwords/hints here - quick win.
      -Admins        Members of all privileged groups.   See who owns the domain; pick a target.
      -AsrepRoast    Users with preauth disabled.         Request AS-REP, crack offline (no creds needed).
      -Kerberoast    Users with an SPN.                   Request TGS, crack service-account passwords offline.
      -Delegation    Unconstrained + constrained deleg.   Impersonation paths to higher privilege.
      -RBCD          Resource-based constrained deleg.    Objects you may be able to abuse to take over a host.
      -PassNotReq    PASSWD_NOTREQD accounts.             May log in with a blank password.
      -AdminCount    adminCount=1 objects.                Currently/formerly privileged - high-value targets.
      -LAPS          Readable LAPS local-admin passwords. If you can read it, instant local admin.
      -Trusts        Domain trusts.                       Routes into other domains/forests.
      -Group <name>  Members of one group (nested-aware). Chase group-in-group paths net.exe misses.
      -User  <name>  One user's key attrs, UAC decoded.   Quick profile: groups, SPNs, flags, pwd age.
      -Query <ldap>  Raw LDAP query, dumps all props.     Anything the named switches don't cover.
         [-Attr x]   ...with -Query, print only attr x.   e.g. -Query "(name=bob)" -Attr memberof
      -All           Everything above that needs no arg.  One-shot recon sweep.

    ============================== HOW TO RUN ===============================
    1) Interactive - dot-source it, then run raw LDAP queries yourself:
         powershell -ep bypass
         . .\enum-ad.ps1
         LDAPSearch -LDAPQuery "(samAccountType=805306368)"
         $g = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Domain Admins))"
         $g.properties.member

    2) Convenience switches - run the script directly:
         .\enum-ad.ps1 -All
         .\enum-ad.ps1 -Descriptions
         .\enum-ad.ps1 -Group "Sales Department"
         .\enum-ad.ps1 -User jeffadmin

    TIP: data goes to the pipeline, headers go to the screen, so you can redirect
         to build wordlists cleanly:   .\enum-ad.ps1 -Users > users.txt
#>

param(
    [switch]$Users,
    [switch]$Groups,
    [switch]$Computers,
    [switch]$Descriptions,
    [switch]$Admins,
    [switch]$AsrepRoast,
    [switch]$Kerberoast,
    [switch]$Delegation,
    [switch]$RBCD,
    [switch]$PassNotReq,
    [switch]$AdminCount,
    [switch]$LAPS,
    [switch]$Trusts,
    [string]$Group,
    [string]$User,
    [string]$Query,
    [string]$Attr,
    [switch]$All,
    [switch]$Help
)

# --- LDAP path, built once and cached -------------------------------------
# Lives inside a function so merely dot-sourcing the file does no AD work.
function Get-LDAPPath {
    if (-not $script:LDAPPath) {
        # PdcRoleOwner = the PDC-emulator DC, the most up-to-date DC to query.
        $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
        # ([adsi]'') starts at the top of the tree; returns the domain DN, correctly formatted.
        $DN  = ([adsi]'').distinguishedName
        $script:LDAPPath = "LDAP://$PDC/$DN"
    }
    $script:LDAPPath
}

# --- Core query function ---------------------------------------------------
# DirectoryEntry = the LDAP path (top of the tree = search root).
# DirectorySearcher runs the query; FindAll() returns every match.
function LDAPSearch {
    param(
        [string]$LDAPQuery
    )
    $DirectoryEntry    = New-Object System.DirectoryServices.DirectoryEntry((Get-LDAPPath))
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    $DirectorySearcher.PageSize = 1000   # don't cap results at the default 1000
    return $DirectorySearcher.FindAll()
}

# --- Small shared helpers --------------------------------------------------
# samAccountType 805306368 (0x30000000) = normal user accounts.
$script:USERFILTER = "samAccountType=805306368"

function Get-CnFromDN { param([string]$dn) ($dn -split ",")[0] -replace "^CN=","" }

# First value of a property, or "" if absent. DirectorySearcher lowercases keys.
function Get-Prop { param($props, [string]$k) if ($props[$k]) { $props[$k][0] } else { "" } }

# Decode the useraccountcontrol bitmask into readable flags.
function ConvertFrom-UAC {
    param([int]$uac)
    $f = @()
    if ($uac -band 0x2)       { $f += "DISABLED" }
    if ($uac -band 0x10)      { $f += "LOCKED_OUT" }
    if ($uac -band 0x20)      { $f += "PASSWD_NOTREQD" }
    if ($uac -band 0x10000)   { $f += "DONT_EXPIRE_PASSWORD" }
    if ($uac -band 0x80000)   { $f += "TRUSTED_FOR_DELEGATION" }        # unconstrained
    if ($uac -band 0x400000)  { $f += "DONT_REQ_PREAUTH" }             # AS-REP roastable
    if ($uac -band 0x1000000) { $f += "TRUSTED_TO_AUTH_FOR_DELEGATION" } # constrained (protocol transition)
    if ($f.Count) { $f -join ", " } else { "none" }
}

# AD timestamps are FILETIME (100ns ticks since 1601). 0 / max = never.
function Convert-FileTime {
    param($ft)
    $v = 0; [void][Int64]::TryParse([string]$ft, [ref]$v)
    if ($v -le 0) { "never/0" }
    elseif ($v -ge 9223372036854775807) { "never" }
    else { try { ([datetime]::FromFileTimeUtc($v)).ToString("u") } catch { "$v" } }
}

# --- Property printer (raw -Query) -----------------------------------------
function Show-Properties {
    param($Results, [string]$OnlyAttr)
    foreach ($obj in $Results) {
        if ($OnlyAttr) {
            $obj.Properties[$OnlyAttr]
        } else {
            foreach ($prop in $obj.Properties) { $prop }
            Write-Host "-------------------------------"
        }
    }
}

# --- Sections (all route through LDAPSearch) -------------------------------

function Get-AllUsers {
    Write-Host "[+] Users" -ForegroundColor Green
    LDAPSearch "($script:USERFILTER)" |
        ForEach-Object { $_.Properties["samaccountname"][0] } | Sort-Object
}

function Get-AllGroups {
    Write-Host "[+] Groups" -ForegroundColor Green
    LDAPSearch "(objectCategory=group)" |
        ForEach-Object { $_.Properties["name"][0] } | Sort-Object
}

function Get-AllComputers {
    Write-Host "[+] Computers" -ForegroundColor Green
    LDAPSearch "(objectCategory=computer)" |
        ForEach-Object {
            $n  = $_.Properties["name"][0]
            $os = if ($_.Properties["operatingsystem"]) { $_.Properties["operatingsystem"][0] } else { "?" }
            "{0,-20} {1}" -f $n, $os
        } | Sort-Object
}

function Get-Descriptions {
    # Descriptions on users/computers frequently leak passwords or hints.
    Write-Host "[+] Objects with a description (check for creds)" -ForegroundColor Yellow
    LDAPSearch "(&(|($script:USERFILTER)(objectCategory=computer))(description=*))" |
        ForEach-Object {
            "{0,-22} {1}" -f $_.Properties["samaccountname"][0], $_.Properties["description"][0]
        } | Sort-Object
}

function Get-Admins {
    # Members of the common privileged groups, in one pass.
    Write-Host "[+] Privileged group members" -ForegroundColor Yellow
    $groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators",
                "Account Operators","Backup Operators","Server Operators","Print Operators","DnsAdmins")
    foreach ($gn in $groups) {
        foreach ($r in (LDAPSearch "(&(objectCategory=group)(cn=$gn))")) {
            if ($r.Properties["member"]) {
                foreach ($m in $r.Properties["member"]) {
                    "{0,-22} <- {1}" -f (Get-CnFromDN $m), $gn
                }
            }
        }
    }
}

function Get-AsrepRoastable {
    # userAccountControl bit 0x400000 (4194304) = DONT_REQ_PREAUTH.
    # :1.2.840.113556.1.4.803: is LDAP's bitwise-AND matching rule.
    Write-Host "[+] AS-REP roastable (no Kerberos pre-auth)" -ForegroundColor Yellow
    LDAPSearch "(&($script:USERFILTER)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" |
        ForEach-Object { $_.Properties["samaccountname"][0] } | Sort-Object
}

function Get-Kerberoastable {
    # Any user object carrying an SPN can be Kerberoasted. krbtgt excluded as noise.
    Write-Host "[+] Kerberoastable (has SPN)" -ForegroundColor Yellow
    LDAPSearch "(&($script:USERFILTER)(servicePrincipalName=*)(!(samaccountname=krbtgt)))" |
        ForEach-Object {
            "{0}  ->  {1}" -f $_.Properties["samaccountname"][0], ($_.Properties["serviceprincipalname"] -join ", ")
        } | Sort-Object
}

function Get-Delegation {
    # Unconstrained: UAC bit 0x80000 (524288) TRUSTED_FOR_DELEGATION.
    Write-Host "[+] Unconstrained delegation" -ForegroundColor Yellow
    LDAPSearch "(userAccountControl:1.2.840.113556.1.4.803:=524288)" |
        ForEach-Object { $_.Properties["samaccountname"][0] } | Sort-Object
    # Constrained: msDS-AllowedToDelegateTo lists the SPNs it can delegate to.
    Write-Host "[+] Constrained delegation" -ForegroundColor Yellow
    LDAPSearch "(msDS-AllowedToDelegateTo=*)" |
        ForEach-Object {
            "{0}  ->  {1}" -f $_.Properties["samaccountname"][0], ($_.Properties["msds-allowedtodelegateto"] -join ", ")
        } | Sort-Object
}

function Get-RBCD {
    # Resource-based constrained delegation: the security descriptor in
    # msDS-AllowedToActOnBehalfOfOtherIdentity names who can impersonate to this object.
    Write-Host "[+] Resource-based constrained delegation (RBCD configured)" -ForegroundColor Yellow
    LDAPSearch "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" |
        ForEach-Object { $_.Properties["samaccountname"][0] } | Sort-Object
}

function Get-PassNotReq {
    # UAC bit 0x20 (32) PASSWD_NOTREQD - account may allow a blank password.
    Write-Host "[+] PASSWD_NOTREQD accounts" -ForegroundColor Yellow
    LDAPSearch "(&($script:USERFILTER)(userAccountControl:1.2.840.113556.1.4.803:=32))" |
        ForEach-Object { $_.Properties["samaccountname"][0] } | Sort-Object
}

function Get-AdminCountObjects {
    # adminCount=1 is stamped on objects that are (or were) in a protected group.
    Write-Host "[+] adminCount=1 (currently or formerly privileged)" -ForegroundColor Yellow
    LDAPSearch "(&(objectCategory=person)(objectClass=user)(adminCount=1))" |
        ForEach-Object { $_.Properties["samaccountname"][0] } | Sort-Object
}

function Get-LAPS {
    # Legacy LAPS stores the local admin password in ms-Mcs-AdmPwd; Windows LAPS
    # uses msLAPS-Password (JSON). You only see a value if you have read rights.
    Write-Host "[+] LAPS passwords (only shown where you can read them)" -ForegroundColor Yellow
    $hits = LDAPSearch "(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*))"
    if ($hits.Count -eq 0) {
        Write-Host "    (none readable - LAPS not deployed, or no rights on the attribute)"
        return
    }
    $hits | ForEach-Object {
        $name = Get-Prop $_.Properties "name"
        $pw   = if ($_.Properties["ms-mcs-admpwd"]) { $_.Properties["ms-mcs-admpwd"][0] }
                else { $_.Properties["mslaps-password"][0] }
        "{0,-20} {1}" -f $name, $pw
    } | Sort-Object
}

function Get-UserInfo {
    param([string]$Name)
    Write-Host "[+] $Name" -ForegroundColor Green
    $res = LDAPSearch "(&($script:USERFILTER)(samaccountname=$Name))"
    if ($res.Count -eq 0) { Write-Host "    (user not found)"; return }
    $p = $res[0].Properties
    "DistinguishedName : " + (Get-Prop $p "distinguishedname")
    "Description       : " + (Get-Prop $p "description")
    $uac = 0; [void][int]::TryParse([string](Get-Prop $p "useraccountcontrol"), [ref]$uac)
    "UAC               : $uac  [" + (ConvertFrom-UAC $uac) + "]"
    "PwdLastSet        : " + (Convert-FileTime (Get-Prop $p "pwdlastset"))
    "LastLogon         : " + (Convert-FileTime (Get-Prop $p "lastlogon"))
    if ($p["serviceprincipalname"]) { "SPNs              : " + ($p["serviceprincipalname"] -join ", ") }
    if ($p["memberof"]) {
        "MemberOf          :"
        $p["memberof"] | ForEach-Object { "    " + (Get-CnFromDN $_) } | Sort-Object
    }
}

function Get-GroupMembers {
    param([string]$GroupName)
    Write-Host "[+] Members of '$GroupName'" -ForegroundColor Green
    # cn=$GroupName* so partial names work too.
    $res = LDAPSearch "(&(objectCategory=group)(cn=$GroupName*))"
    if ($res.Count -eq 0) { Write-Host "    (group not found)"; return }
    foreach ($r in $res) {
        if ($r.Properties["member"]) {
            # A member whose DN isn't under CN=Users / an OU is likely a NESTED group - chase it.
            $r.Properties["member"] | ForEach-Object {
                $cn = Get-CnFromDN $_
                if ($_ -notmatch "CN=Users," -and $_ -notmatch "OU=") {
                    "{0}   <- possible nested group, enumerate it too" -f $cn
                } else {
                    $cn
                }
            } | Sort-Object
        } else { Write-Host "    (no members)" }
    }
}

# --- On-screen usage (printed on -Help or when run with no options) --------
function Show-Usage {
    Write-Host "enum-ad.ps1 - AD enumeration over LDAP (basic user, no RSAT)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "USAGE:  .\enum-ad.ps1 [option]"
    Write-Host ""
    Write-Host "OPTIONS (what each is for):"
    $rows = @(
        @("-Users",        "every user account - build a spray/userlist"),
        @("-Groups",       "every group - spot custom/odd groups to dig into"),
        @("-Computers",    "computers + OS - find servers, old OSes, targets"),
        @("-Descriptions", "objects with a description set - admins hide passwords here"),
        @("-Admins",       "members of all privileged groups - who owns the domain"),
        @("-AsrepRoast",   "users with preauth off - crack AS-REP offline, no creds needed"),
        @("-Kerberoast",   "users with an SPN - crack service-account passwords offline"),
        @("-Delegation",   "unconstrained + constrained delegation - impersonation paths"),
        @("-RBCD",         "resource-based constrained delegation - host-takeover abuse"),
        @("-PassNotReq",   "PASSWD_NOTREQD accounts - may allow a blank password"),
        @("-AdminCount",   "adminCount=1 objects - currently/formerly privileged"),
        @("-LAPS",         "readable LAPS local-admin passwords - instant local admin"),
        @("-Trusts",       "domain trusts - routes into other domains/forests"),
        @("-Group <name>", "members of one group, flags nested groups"),
        @("-User <name>",  "one user profiled: groups, SPNs, UAC flags, pwd age"),
        @("-Query <ldap>", "raw LDAP query, dumps all properties of matches"),
        @("  -Attr <x>",   "with -Query: print only attribute x"),
        @("-All",          "run every section above that needs no argument")
    )
    foreach ($r in $rows) { Write-Host ("  {0,-16} {1}" -f $r[0], $r[1]) }
    Write-Host ""
    Write-Host "EXAMPLES:"
    Write-Host "  .\enum-ad.ps1 -All"
    Write-Host "  .\enum-ad.ps1 -Descriptions"
    Write-Host "  .\enum-ad.ps1 -Group `"Sales Department`""
    Write-Host "  .\enum-ad.ps1 -User jeffadmin"
    Write-Host "  .\enum-ad.ps1 -Users > users.txt        # clean list, headers stay on screen"
    Write-Host "  . .\enum-ad.ps1 ; LDAPSearch -LDAPQuery `"(objectClass=group)`"   # interactive"
}

# --- Main (only runs when the script is executed directly) -----------------
function Invoke-Main {
    Write-Host ("[*] LDAP: " + (Get-LDAPPath)) -ForegroundColor Cyan
    Write-Host ""

    $ran = $false
    if ($Help)                    { Show-Usage; return }
    if ($Query)                   { Show-Properties (LDAPSearch $Query) $Attr; Write-Host ""; $ran = $true }
    if ($User)                    { Get-UserInfo $User;      Write-Host ""; $ran = $true }
    if ($All -or $Users)          { Get-AllUsers;            Write-Host ""; $ran = $true }
    if ($All -or $Groups)         { Get-AllGroups;           Write-Host ""; $ran = $true }
    if ($All -or $Computers)      { Get-AllComputers;        Write-Host ""; $ran = $true }
    if ($All -or $Descriptions)   { Get-Descriptions;        Write-Host ""; $ran = $true }
    if ($All -or $Admins)         { Get-Admins;              Write-Host ""; $ran = $true }
    if ($All -or $AsrepRoast)     { Get-AsrepRoastable;      Write-Host ""; $ran = $true }
    if ($All -or $Kerberoast)     { Get-Kerberoastable;      Write-Host ""; $ran = $true }
    if ($All -or $Delegation)     { Get-Delegation;          Write-Host ""; $ran = $true }
    if ($All -or $RBCD)           { Get-RBCD;                Write-Host ""; $ran = $true }
    if ($All -or $PassNotReq)     { Get-PassNotReq;          Write-Host ""; $ran = $true }
    if ($All -or $AdminCount)     { Get-AdminCountObjects;   Write-Host ""; $ran = $true }
    if ($All -or $LAPS)           { Get-LAPS;                Write-Host ""; $ran = $true }
    if ($All -or $Trusts)         { Get-Trusts;              Write-Host ""; $ran = $true }
    if ($Group)                   { Get-GroupMembers $Group; Write-Host ""; $ran = $true }

    if (-not $ran) {
        $u = (LDAPSearch "($script:USERFILTER)").Count
        $g = (LDAPSearch "(objectCategory=group)").Count
        $c = (LDAPSearch "(objectCategory=computer)").Count
        Write-Host "[*] Summary: $u users, $g groups, $c computers." -ForegroundColor Cyan
        Write-Host ""
        Show-Usage
    }
}

function Get-Trusts {
    Write-Host "[+] Domain trusts" -ForegroundColor Yellow
    LDAPSearch "(objectClass=trustedDomain)" |
        ForEach-Object {
            "{0,-25} trustDirection={1}" -f $_.Properties["name"][0], $_.Properties["trustdirection"][0]
        } | Sort-Object
}

# Dot-sourcing (. .\enum-ad.ps1) sets InvocationName to '.', exposing the
# functions WITHOUT running Main. Running the script by name runs Main.
if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
