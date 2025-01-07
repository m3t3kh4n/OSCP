# Table of Contents

# MindMap Checklist
- password sparying: Get all users (enum4linux) > Get password minimum character count > Complexity (if yes: Uppercase, smallcase, special char, number)
- Kerberoasting
- Pass the ticket
- password cracking
- username enum: Kerbrute
- shadow credentials (https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- DCSync

# Cheat Sheet

# Toolset:
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1): AD Enum, for example finding users that are vulnerable to Kerberoasting and AS-REP Roasting
- [SharpView](https://github.com/dmchell/SharpView): The same as PowerView
- [BloodHound](https://github.com/BloodHoundAD/BloodHound): GUI AD Relations
- [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors): Data Collector for BloodHound in json to import BloodHound
- [BoodHound.py](https://github.com/fox-it/BloodHound.py): **can be run from non-domain joined attack host**. Same as sharphound
- [KerBrute](https://github.com/ropnop/kerbrute): enum AD account, password spraying, brute-forcing
- [Impacket](https://github.com/SecureAuthCorp/impacket):
- [Responder](https://github.com/lgandx/Responder): LLMNR, NBT-NS, MDNS poisoning
- [Inveigh.ps1](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1): similar to Reesponder, but in PowerShell
- [C# Inveigh \(Inveigh Zero\)](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh): C# version of Inveigh
- [rpcinfo](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcinfo): AD enum via remote RPC service
- [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html): similar to rpcinfo
- [CrackMapExec \(CME\)](https://github.com/byt3bl33d3r/CrackMapExec): enum, attack, post-exploitation in services like SMB, WMI, WinRM, MSSQL
- [Rubeus](https://github.com/GhostPack/Rubeus): Kerberos Abuse
- [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py): finding Service Principal Names tied to normal users
- [HashCat](https://hashcat.net/hashcat/): password crack
- [enum4linux](https://github.com/CiscoCXSecurity/enum4linux): enum SMB
- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng): enum SMB (newer version)
- [ldapsearch](https://linux.die.net/man/1/ldapsearch)
- [windapsearch](https://github.com/ropnop/windapsearch)
- [DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray): PowerShell password spraying
- [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit): audit and attack Microsoft's Local Administrator Password Solution (LAPS)
- [smbmap](https://github.com/ShawnDEvans/smbmap): SMB share enum
- [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py): semi-interactive shell
- [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py): command exec over wmi
- [Snaffler](https://github.com/SnaffCon/Snaffler): finding passwords in AD computers with access to file shares
- [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py): SMB server
- [setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)): add/read/modify/delete Service Principal Names (SPNs) directory property for an Active Directory service account
- [Mimikatz](https://github.com/ParrotSec/mimikatz): pass-the-hash attacks, extract plaintext passwords, Kerberos ticket extraction from memory
- [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py): Remote SAM/LSA secrets damp
- [evil-winrm](https://github.com/Hackplayers/evil-winrm): interactive shell over WinRM
- [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py): interact to MSSQL dbs
- [noPac.py](https://github.com/Ridter/noPac): Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
- [rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py): RPC endpoint mapper
- [CVE-2021-1675.py](https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py): Printnightmare
- [ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py): SMB relay attack
- [PetitPotam.py](https://github.com/topotam/PetitPotam): CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions
- [gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py):	Tool for manipulating certificates and TGTs.
- [getnthash.py](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py):	use an existing TGT to request a PAC for the current user using U2U.
- [adidnsdump](https://github.com/dirkjanm/adidnsdump): enumerating and dumping DNS records from a domain (DNS Zone Transfer)
- [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt): extract username and pw from Group Policy prereferences
- [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py): AS-REP Roasting (AS-REP hashes for users with the 'Do not require Kerberos preauthentication' set)
- [lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py): SID bruteforcing
- [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py): creation and customization of TGT/TGS tickets. It can be used for Golden Ticket creation, child to parent trust attacks
- [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py): automated child to parent domain privilege escalation
- [Active Directory Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer): AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for offline analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions.
- [PingCastle](https://www.pingcastle.com/documentation/): auditing the security level of an AD environment based on a risk assessment and maturity framework (based on CMMI adapted to AD security).
- [Group3r](https://github.com/Group3r/Group3r): auditing and finding security misconfigurations in AD Group Policy Objects (GPO)
- [ADRecon](https://github.com/adrecon/ADRecon): extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state


## Active Directory Enumeration & Attacks

### Setting The Stage

#### Introduction to Active Directory Enumeration & Attacks
##### Active Directory Explained
##### Why Should We Care About AD?
##### Real-World Examples
##### This Is The Way
##### Practical Examples
##### Toolkit

#### Tools of the Trade

**Username Enumeration** (find valid usernames)
 - Kerbrute in conjunction with the jsmith.txt or jsmith2.txt (https://github.com/insidetrust/statistically-likely-usernames)
 - https://github.com/ropnop/kerbrute/releases/tag/v1.0.3
```
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

Identifying Potential Vulnerabilities
The local system account NT AUTHORITY\SYSTEM is a built-in account in Windows operating systems. It has the highest level of access in the OS and is used to run most Windows services. It is also very common for third-party services to run in the context of this account by default. A SYSTEM account on a domain-joined host will be able to enumerate Active Directory by impersonating the computer account, which is essentially just another kind of user account. Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.

There are several ways to gain SYSTEM-level access on a host, including but not limited to:

Remote Windows exploits such as MS08-067, EternalBlue, or BlueKeep.
Abusing a service running in the context of the SYSTEM account, or abusing the service account SeImpersonate privileges using Juicy Potato. This type of attack is possible on older Windows OS' but not always possible with Windows Server 2019.
Local privilege escalation flaws in Windows operating systems such as the Windows 10 Task Scheduler 0-day.
Gaining admin access on a domain-joined host with a local account and using Psexec to launch a SYSTEM cmd window
By gaining SYSTEM-level access on a domain-joined host, you will be able to perform actions such as, but not limited to:

Enumerate the domain using built-in tools or offensive tools such as BloodHound and PowerView.
Perform Kerberoasting / ASREPRoasting attacks within the same domain.
Run tools such as Inveigh to gather Net-NTLMv2 hashes or perform SMB relay attacks.
Perform token impersonation to hijack a privileged domain user account.
Carry out ACL attacks.

### LLMNR/NBT-NS Poisoning

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port 5355 over UDP natively. If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port 137 over UDP.

The kicker here is that when LLMNR/NBT-NS are used for name resolution, ANY host on the network can reply. This is where we come in with Responder to poison these requests. With network access, we can spoof an authoritative name resolution source ( in this case, a host that's supposed to belong in the network segment ) in the broadcast domain by responding to LLMNR and NBT-NS traffic as if they have an answer for the requesting host. This poisoning effort is done to get the victims to communicate with our system by pretending that our rogue system knows the location of the requested host. If the requested host requires name resolution or authentication actions, we can capture the NetNTLM hash and subject it to an offline brute force attack in an attempt to retrieve the cleartext password. The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host. LLMNR/NBNS spoofing combined with a lack of SMB signing can often lead to administrative access on hosts within a domain. SMB Relay attacks will be covered in a later module about Lateral Movement.

Quick Example - LLMNR/NBT-NS Poisoning
Let's walk through a quick example of the attack flow at a very high level:
1. A host attempts to connect to the print server at \\print01.inlanefreight.local, but accidentally types in \\printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \\printer01.inlanefreight.local.
4. The attacker (us with Responder running) responds to the host stating that it is the \\printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

Several tools can be used to attempt LLMNR & NBT-NS poisoning:

Tool	Description
- Responder	Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.
- Inveigh	Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.
- Metasploit	Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.

Linux:

We must run the tool with sudo privileges or as root and make sure the following ports are available on our attack host for it to function best:

```
sudo responder -I <interface-name>
```
NetNTLMv2 hashes are very useful once cracked, but cannot be used for techniques such as pass-the-hash
```
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```

#Windows

```
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters
```
```
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```
or:
```
.\Inveigh.exe
```
For Inveigh.exe Press ESC to enter/exit interactive console, which is very useful while running the tool. The console gives us access to captured credentials/hashes, allows us to stop Inveigh, and more. After typing HELP and hitting enter, we are presented with several options. We can quickly view unique captured hashes by typing `GET NTLMV2UNIQUE`. We can type in `GET NTLMV2USERNAMES` and see which usernames we have collected. This is helpful if we want a listing of users to perform additional enumeration against and see which are worth attempting to crack offline using Hashcat.
```
GET NTLMV2UNIQUE
GET NTLMV2USERNAMES
```

> We can disable LLMNR in Group Policy by going to Computer Configuration --> Administrative Templates --> Network --> DNS Client and enabling "Turn OFF Multicast Name Resolution."

> NBT-NS cannot be disabled via Group Policy but must be disabled locally on each host. We can do this by opening Network and Sharing Center under Control Panel, clicking on Change adapter settings, right-clicking on the adapter to view its properties, selecting Internet Protocol Version 4 (TCP/IPv4), and clicking the Properties button, then clicking on Advanced and selecting the WINS tab and finally selecting Disable NetBIOS over TCP/IP.

> While it is not possible to disable NBT-NS directly via GPO, we can create a PowerShell script under Computer Configuration --> Windows Settings --> Script (Startup/Shutdown) --> Startup with something like the following:

```
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```

In the Local Group Policy Editor, we will need to double click on Startup, choose the PowerShell Scripts tab, and select "For this GPO, run scripts in the following order" to Run Windows PowerShell scripts first, and then click on Add and choose the script. For these changes to occur, we would have to either reboot the target system or restart the network adapter.

To push this out to all hosts in a domain, we could create a GPO using Group Policy Management on the Domain Controller and host the script on the SYSVOL share in the scripts folder and then call it via its UNC path such as:

```
\\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts
```
Once the GPO is applied to specific OUs and those hosts are restarted, the script will run at the next reboot and disable NBT-NS, provided that the script still exists on the SYSVOL share and is accessible by the host over the network.

Other mitigations include filtering network traffic to block LLMNR/NetBIOS traffic and enabling SMB Signing to prevent NTLM relay attacks. Network intrusion detection and prevention systems can also be used to mitigate this activity, while network segmentation can be used to isolate hosts that require LLMNR or NetBIOS enabled to operate correctly.

Detection
It is not always possible to disable LLMNR and NetBIOS, and therefore we need ways to detect this type of attack behavior. One way is to use the attack against the attackers by injecting LLMNR and NBT-NS requests for non-existent hosts across different subnets and alerting if any of the responses receive answers which would be indicative of an attacker spoofing name resolution responses. This [blog post](https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/) explains this method more in-depth.

Furthermore, hosts can be monitored for traffic on ports UDP 5355 and 137, and event IDs 4697 and 7045 can be monitored for. Finally, we can monitor the registry key `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` for changes to the `EnableMulticast` DWORD value. A value of `0` would mean that LLMNR is disabled.






# References:
- https://github.com/initstring/linkedin2username
- https://github.com/insidetrust/statistically-likely-usernames
- IMPORTANT: https://github.com/dafthack/DomainPasswordSpray
- HashCat d3ad0ne rule: https://github.com/hashcat/hashcat/blob/master/rules/d3ad0ne.rule
- SMB Responder SCF file attacks: https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/
- CMMI: https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration
