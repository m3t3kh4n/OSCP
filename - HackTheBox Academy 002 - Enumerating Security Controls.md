# Enumerating Security Controls

## Windows Defender

get current defender status
```
Get-MpComputerStatus
```
- `RealTimeProtectionEnabled` parameter is set to True

## AppLocker

AppLocker is Microsoft's application whitelisting solution and gives system administrators control over which applications and files users can run. It provides granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers. It is common for organizations to block cmd.exe and PowerShell.exe and write access to certain directories, but this can all be bypassed. Organizations also often focus on blocking the PowerShell.exe executable, but forget about the other PowerShell executable locations such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`. We can see that this is the case in the AppLocker rules shown below. All Domain Users are disallowed from running the 64-bit PowerShell executable located at: `%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe`

```
Get-AppLockerPolicy
```
```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

## PowerShell Constrained Language Mode
PowerShell Constrained Language Mode locks down many of the features needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more. We can quickly enumerate whether we are in Full Language Mode or Constrained Language Mode.

```
$ExecutionContext.SessionState.LanguageMode
```

## LAPS 

Local Administrator Password Solution (LAPS) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement

One is parsing `ExtendedRights` for all computers with LAPS enabled. This will show groups specifically delegated to read LAPS passwords, which are often users in protected groups. An account that has joined a computer to a domain receives `All Extended Rights` over that host, and this right gives the account the ability to read passwords. Enumeration may show a user account that can read the LAPS password on a host. This can help us target specific AD users who can read LAPS passwords.

```
Find-LAPSDelegatedGroups
```

The `Find-AdmPwdExtendedRights` checks the rights on each computer with LAPS enabled for any groups with read access and users with "`All Extended Rights`". Users with "`All Extended Rights`" can read LAPS passwords and may be less protected than users in delegated groups, so this is worth checking for.


```
Find-AdmPwdExtendedRights
```

We can use the `Get-LAPSComputers` function to search for computers that have LAPS enabled when passwords expire, and even the randomized passwords in cleartext if our user has access.

```
Get-LAPSComputers
```

# Credentialed Enumeration - from Linux

## CrackMapExec (CME)

CME offers a help menu for each protocol (i.e., `crackmapexec winrm -h`, etc.). Be sure to review the entire help menu and all possible options. For now, the flags we are interested in are:
- `-u` Username The user whose credentials we will use to authenticate
- `-p` Password User's password
- `Target (IP or FQDN)` Target host to enumerate (in our case, the Domain Controller)
- `--users` Specifies to enumerate Domain Users
- `--groups` Specifies to enumerate domain groups
- `--loggedon-users` Attempts to enumerate what users are logged on to a target, if any

**CME - Domain User Enumeration**
```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```
**CME - Domain Group Enumeration**
```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```
**CME - Logged On Users**
```
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```
> local admin because (Pwn3d!)

**Share Enumeration - Domain Controller**
```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```

**Spider_plus**
`spider_plus` will dig through each readable share on the host and list all readable files.
```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```

**SMBMap To Check Access**
what our user can access and their permission levels
```
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```
**Recursive List Of All Directories**
```
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

## rpcclient

**SMB NULL Session with rpcclient**
```
rpcclient -U "" -N 172.16.5.5
```
While looking at users in rpcclient, you may notice a field called `rid`: beside each user. A _Relative Identifier (RID)_ is a unique identifier (represented in hexadecimal format) utilized by Windows to track and identify objects. To explain how this fits in, let's look at the examples below:

- The SID for the INLANEFREIGHT.LOCAL domain is: S-1-5-21-3842939050-3880317879-2865463114.
- When an object is created within a domain, the number above _(SID) will be combined with a RID_ to make a unique value used to represent the object.
- So the domain user htb-student with a RID:[0x457] Hex 0x457 would = decimal 1111, will have a full user SID of: S-1-5-21-3842939050-3880317879-2865463114-1111.
- This is unique to the htb-student object in the INLANEFREIGHT.LOCAL domain and you will never see this paired value tied to another object in this domain or any other.

However, there are accounts that you will notice that have the same RID regardless of what host you are on. Accounts like the built-in Administrator for a domain will have a RID `[administrator]` `rid:[0x1f4]`, which, when converted to a decimal value, equals 500. ***The built-in Administrator account will always have the RID value Hex 0x1f4, or 500. This will always be the case***. Since this value is unique to an object, we can use it to enumerate further information about it from the domain. Let's give it a try again with rpcclient. We will dig a bit targeting the htb-student user.

**RPCClient User Enumeration By RID**
```
> queryuser 0x457
```

**RPCClient enum all users**
```
> enumdomusers
```

## Impacket Toolkit

**psexec.py**

Psexec.py is a clone of the Sysinternals psexec executable, but works slightly differently from the original. The tool creates a remote service by uploading a randomly-named executable to the ADMIN$ share on the target host. It then registers the service via RPC and the Windows Service Control Manager. Once established, communication happens over a named pipe, providing an interactive remote shell as SYSTEM on the victim host.

***we need credentials for a user with local administrator privileges***

```
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
```

**wmiexec.py**

Wmiexec.py utilizes a semi-interactive shell where commands are executed through Windows Management Instrumentation. It does not drop any files or executables on the target host and generates fewer logs than other modules. After connecting, it runs as the local admin user we connected with (this can be less obvious to someone hunting for an intrusion than seeing SYSTEM executing many commands).

```
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

Note that this shell environment is not fully interactive, so each command issued will execute a new cmd.exe from WMI and execute your command. The downside of this is that if a vigilant defender checks event logs and looks at event ID 4688: A new process has been created, they will see a new process created to spawn cmd.exe and issue a command.


**Windapsearch**

**Windapsearch - Domain Admins**
```
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```

**Windapsearch - Privileged Users**

```
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

**Bloodhound.py**

- SharpHound collector
- BloodHound.py collector (also referred to as an ingestor)
- BloodHound GUI

Once uploaded, we can run various pre-built queries or write custom queries using [Cypher language](https://blog.cptjesus.com/posts/introtocypher).

```
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```
> our nameserver as the Domain Controller with the -ns flag and the domain, INLANEFREIGHt.LOCAL with the -d flag. The -c all flag told the tool to run all checks

```
sudo neo4j start
zip -r ilfreight_bh.zip *.json
```
After zipping upload data option in BloodHound GUI.

***!!!!! https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/ !!!!!***

***!!!!! https://wadcoms.github.io/ !!!!!***

> look at the Database Info tab after uploading data, search for a node such as Domain Users and, scroll through all of the options under the Node Info tab, check out the pre-built queries under the Analysis tab, many which are powerful and can quickly find various ways to domain takeover. Finally, experiment with some custom Cypher queries by selecting some interesting ones from the Cypher cheatsheet linked above, pasting them into the Raw Query box at the bottom, and hitting enter. You can also play with the Settings menu by clicking the gear icon on the right side of the screen and adjusting how nodes and edges are displayed, enable query debug mode, and enable dark mode


## Credentialed Enumeration - from Windows

> SharpHound/BloodHound, PowerView/SharpView, Grouper2, Snaffler

**ActiveDirectory PowerShell Module**

The `Get-Module` cmdlet, which is part of the Microsoft.PowerShell.Core module, will list all available modules, their version, and potential commands for use. This is a great way to see if anything like Git or custom administrator scripts are installed. If the module is not loaded, run `Import-Module ActiveDirectory` to load it for use.

Discover modules:
```
Get-Module
```

Load ActiveDirectory Module
```
Import-Module ActiveDirectory
```

Get Domain info:
```
Get-ADDomain
```

Get kerberoastable AD Accounts
```
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

verify domain trust relationships
```
Get-ADTrust -Filter *
```
This cmdlet will print out any trust relationships the domain has. We can determine if they are trusts within our forest or with domains in other forests, the type of trust, the direction of the trust, and the name of the domain the relationship is with. This will be useful later on when looking to take advantage of child-to-parent trust relationships and attacking across forest trusts

AD group information
```
Get-ADGroup -Filter * | select name
```

get more detailed information about a particular group
```
Get-ADGroup -Identity "Backup Operators"
```

Group Membership
```
Get-ADGroupMember -Identity "Backup Operators"
```

## PowerView

| Command                          | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| **Export-PowerViewCSV**          | Append results to a CSV file                                                |
| **ConvertTo-SID**                | Convert a User or group name to its SID value                               |
| **Get-DomainSPNTicket**          | Requests the Kerberos ticket for a specified Service Principal Name (SPN) account |

### Domain/LDAP Functions:
| Command                          | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| **Get-Domain**                   | Will return the AD object for the current (or specified) domain             |
| **Get-DomainController**         | Return a list of the Domain Controllers for the specified domain            |
| **Get-DomainUser**               | Will return all users or specific user objects in AD                        |
| **Get-DomainComputer**           | Will return all computers or specific computer objects in AD                |
| **Get-DomainGroup**              | Will return all groups or specific group objects in AD                      |
| **Get-DomainOU**                 | Search for all or specific OU objects in AD                                 |
| **Find-InterestingDomainAcl**    | Finds object ACLs in the domain with modification rights set to non-built in objects |
| **Get-DomainGroupMember**        | Will return the members of a specific domain group                          |
| **Get-DomainFileServer**         | Returns a list of servers likely functioning as file servers                |
| **Get-DomainDFSShare**           | Returns a list of all distributed file systems for the current (or specified) domain |

### GPO Functions:
| Command                          | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| **Get-DomainGPO**                | Will return all GPOs or specific GPO objects in AD                          |
| **Get-DomainPolicy**             | Returns the default domain policy or the domain controller policy for the current domain |

### Computer Enumeration Functions:
| Command                          | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| **Get-NetLocalGroup**            | Enumerates local groups on the local or a remote machine                    |
| **Get-NetLocalGroupMember**      | Enumerates members of a specific local group                                |
| **Get-NetShare**                 | Returns open shares on the local (or a remote) machine                      |
| **Get-NetSession**               | Will return session information for the local (or a remote) machine         |
| **Test-AdminAccess**             | Tests if the current user has administrative access to the local (or a remote) machine |

### Threaded 'Meta'-Functions:
| Command                          | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| **Find-DomainUserLocation**      | Finds machines where specific users are logged in                           |
| **Find-DomainShare**             | Finds reachable shares on domain machines                                   |
| **Find-InterestingDomainShareFile** | Searches for files matching specific criteria on readable shares in the domain |
| **Find-LocalAdminAccess**        | Find machines on the local domain where the current user has local administrator access |

### Domain Trust Functions:
| Command                          | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| **Get-DomainTrust**              | Returns domain trusts for the current domain or a specified domain          |
| **Get-ForestTrust**              | Returns all forest trusts for the current forest or a specified forest      |
| **Get-DomainForeignUser**        | Enumerates users who are in groups outside of the user's domain             |
| **Get-DomainForeignGroupMember** | Enumerates groups with users outside of the group's domain and returns each foreign member |
| **Get-DomainTrustMapping**       | Will enumerate all trusts for the current domain and any others seen        |

- provide us with information on all users or specific users we specify

```
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

- Recursive Group Membership: retrieve group-specific information. Adding the -Recurse switch tells PowerView that if it finds any groups that are part of the target group (nested group membership) to list out the members of those groups

```
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

- Trust Enumeration
```
Get-DomainTrustMapping
```

- Testing for Local Admin Access
```
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```

- Finding Users With SPN Set (Kerberoastable)
```
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

## SharpView

- to enumerate information about a specific user
```
.\SharpView.exe Get-DomainUser -Identity forend
```

## Snaffler

Snaffler works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories. Once that is done, it iterates through any directories readable by our user and hunts for files that could serve to better our position within the assessment. _**Snaffler requires that it be run from a domain-joined host or in a domain-user context**_.

```
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

## BloodHound

### SharpHound

```
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```


# Living Off the Land










