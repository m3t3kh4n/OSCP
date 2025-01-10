# Privileged Access

**if we take over an account with local admin rights over a host, or set of hosts, we can perform a `Pass-the-Hash` attack to authenticate via the SMB protocol**

But what if we don't yet have local admin rights on any hosts in the domain? There are several other ways we can move around a Windows domain:
- Remote Desktop Protocol (RDP) - is a remote access/management protocol that gives us GUI access to a target host
- PowerShell Remoting - also referred to as **PSRemoting** or **Windows Remote Management (WinRM)** access, is a remote access protocol that allows us to run commands or enter an interactive command-line session on a remote host using PowerShell
- **MSSQL Server** - an account with sysadmin privileges on an SQL Server instance can log into the instance remotely and execute queries against the database. This access can be used to run operating system commands in the context of the SQL Server service account through various methods

We can enumerate this access in various ways. The easiest, once again, is via BloodHound, as the following edges exist to show us what types of remote access privileges a given user has:
- CanRDP
- CanPSRemote
- SQLAdmin

We can also enumerate these privileges using tools such as PowerView and even built-in tools.

**!!! https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp !!!**

**!!! https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote !!!**

**!!! https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin !!!**


## Remote Desktop

Typically, if we have control of a local admin user on a given machine, we will be able to access it via RDP. Sometimes, we will obtain a foothold with a user that does not have local admin rights anywhere, but does have the rights to RDP into one or more machines.

- **Enumerating the Remote Desktop Users Group**
```
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```

- **Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound**

![image](https://github.com/user-attachments/assets/712f8b98-b426-4a8f-b066-4e30ee2d7f37)

If we gain control over a user through an attack such as LLMNR/NBT-NS Response Spoofing or Kerberoasting, we can search for the username in BloodHound to check what type of remote access rights they have either directly or inherited via group membership under `Execution Rights` on the `Node Info` tab.

- **Checking Remote Access Rights using BloodHound**

![image](https://github.com/user-attachments/assets/38b66cc4-a663-43ed-a193-6cd903d9bebe)

We could also check the `Analysis` tab and run the pre-built queries` Find Workstations where Domain Users can RDP` or `Find Servers where Domain Users can RDP`.

To test this access, we can either use a tool such as `xfreerdp` or `Remmina` from our VM or the Pwnbox or **`mstsc.exe`** if attacking from a Windows host.

## WinRM

- **Enumerating the Remote Management Users Group**

```
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```

- We can also utilize this custom `Cypher query` in BloodHound to hunt for users with this type of access. This can be done by pasting the query into the `Raw Query` box at the bottom of the screen and hitting enter.

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

![image](https://github.com/user-attachments/assets/18da4436-a45c-4023-bfae-295174c63903)

We could also add this as a custom query to our BloodHound installation, so it's always available to us.

![image](https://github.com/user-attachments/assets/c1cd8123-422e-47f2-ad0f-d137636513bf)

- **Establishing WinRM Session from Windows**
```
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```

- **Establishing WinRM Session from Linux**
```
gem install evil-winrm
evil-winrm -i 10.129.201.234 -u forend
```

## SQL Server Admin

BloodHound, once again, is a great bet for finding this type of access via the SQLAdmin edge. We can check for SQL Admin Rights in the Node Info tab for a given user or use this custom Cypher query to search:

- **Using a Custom Cypher Query to Check for SQL Admin Rights in BloodHound**
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

![image](https://github.com/user-attachments/assets/ef9f5c01-26b4-409f-b81c-94686831751e)

- **Enumerating MSSQL Instances with PowerUpSQL**
```
cd .\PowerUpSQL\
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
```

We could then authenticate against the remote SQL server host and run custom queries or operating system commands. It is worth experimenting with this tool, but extensive enumeration and attack tactics against MSSQL are outside this module's scope.

```
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

Reference: https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet

- We can also authenticate from our Linux attack host using `mssqlclient.py` from the Impacket toolkit.
```
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```

- We could then choose `enable_xp_cmdshell` to enable the `xp_cmdshell` stored procedure which allows for one to execute operating system commands via the database if the account in question has the proper access rights.
```
enable_xp_cmdshell
```
- Finally, we can run commands in the format `xp_cmdshell <command>`. Here we can enumerate the rights that our user has on the system and see that we have `SeImpersonatePrivilege`, which can be leveraged in combination with a tool such as `JuicyPotato`, `PrintSpoofer`, or `RoguePotato` to escalate to `SYSTEM` level privileges, depending on the target host, and use this access to continue toward our goal. These methods are covered in the `SeImpersonate` and `SeAssignPrimaryToken` of the Windows Privilege Escalation module.

```
xp_cmdshell whoami /priv
```

Reference: https://github.com/ohpe/juicy-potato

Reference: https://github.com/itm4n/PrintSpoofer

Reference: https://github.com/antonioCoco/RoguePotato

> ***Finally, whenever we find SQL credentials (in a script, a web.config file, or another type of database connection string), we should test access against any MSSQL servers in the environment. This type of access is almost guaranteed `SYSTEM` access over a host. If we can run commands as the account we authenticate with, it will almost always have the dangerous `SeImpersonatePrivilege` right.***





































