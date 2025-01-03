![image](https://github.com/user-attachments/assets/2b757fa4-d326-4dab-822f-e05e15a6524b)# HackTheBox Academy - Active Directory

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
- 


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


# References:
- https://github.com/initstring/linkedin2username
- https://github.com/insidetrust/statistically-likely-usernames
- IMPORTANT: https://github.com/dafthack/DomainPasswordSpray
- HashCat d3ad0ne rule: https://github.com/hashcat/hashcat/blob/master/rules/d3ad0ne.rule
- SMB Responder SCF file attacks: https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/
