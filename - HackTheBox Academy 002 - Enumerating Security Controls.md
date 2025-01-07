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


















