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
