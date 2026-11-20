# enum-ad

Active Directory enumeration over LDAP, in a single PowerShell script.

It uses only `System.DirectoryServices` (DirectoryEntry + DirectorySearcher) and
ADSI, so it needs **nothing but a basic domain user** — no RSAT, no imported
modules, no admin rights. Run it on any domain-joined Windows host.

## Usage

```powershell
powershell -ep bypass
.\enum-ad.ps1 -Help      # list every option and what it's for
.\enum-ad.ps1 -All       # full recon sweep
```

### Options

| Option | What it's for |
|---|---|
| `-Users` | Every user account — build a spray/userlist |
| `-Groups` | Every group — spot custom/odd groups to dig into |
| `-Computers` | Computers + OS — find servers, old OSes, targets |
| `-Descriptions` | Objects with a description set — admins hide passwords here |
| `-Admins` | Members of all privileged groups — who owns the domain |
| `-AsrepRoast` | Users with preauth off — crack AS-REP offline, no creds needed |
| `-Kerberoast` | Users with an SPN — crack service-account passwords offline |
| `-Delegation` | Unconstrained + constrained delegation — impersonation paths |
| `-RBCD` | Resource-based constrained delegation — host-takeover abuse |
| `-PassNotReq` | `PASSWD_NOTREQD` accounts — may allow a blank password |
| `-AdminCount` | `adminCount=1` objects — currently/formerly privileged |
| `-LAPS` | Readable LAPS local-admin passwords — instant local admin |
| `-Trusts` | Domain trusts — routes into other domains/forests |
| `-Group <name>` | Members of one group, flags nested groups |
| `-User <name>` | One user profiled: groups, SPNs, UAC flags, pwd age |
| `-Query <ldap>` | Raw LDAP query, dumps all properties of matches |
| `-Query <ldap> -Attr <x>` | ...print only attribute `x` |
| `-All` | Run every section that needs no argument |

Headers print to the screen and data goes to the pipeline, so you can redirect
to build clean lists:

```powershell
.\enum-ad.ps1 -Users > users.txt
```

### Interactive use

Dot-source the script to load its core function without running anything, then
issue raw LDAP queries yourself:

```powershell
. .\enum-ad.ps1
LDAPSearch -LDAPQuery "(objectClass=group)"
$g = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Domain Admins))"
$g.properties.member
```

## How it works

1. Find the PDC-emulator DC via the `Domain` .NET class (`PdcRoleOwner`) and the
   domain DN via ADSI (`([adsi]'').distinguishedName`), then build the
   `LDAP://<PDC>/<DN>` path.
2. `DirectoryEntry` binds to that path (the top of the tree); `DirectorySearcher`
   runs an LDAP filter against it and `FindAll()` returns the matches.
3. Each option is just a pre-written LDAP filter over that one search function.

The roasting/delegation filters use the LDAP bitwise-AND matching rule
(`1.2.840.113556.1.4.803`) against `userAccountControl` — e.g. `0x400000`
(DONT_REQ_PREAUTH) for AS-REP roastable accounts.

## Related

- [creds-hunting](https://github.com/SageSchiller/creds-hunting) — fast read-only credential hunting: Linux + Windows local sweeps and a Kali-side DB-dump parser (user:pass + hashes, UTF-16-safe).

## Note

For authorized security testing, labs, and CTFs. Read-only LDAP enumeration —
it queries the directory, it does not change anything.
