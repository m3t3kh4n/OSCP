# Active Directory Overview

## Active Directory Structure

Active Directory is arranged in a hierarchical tree structure, with a forest at the top containing one or more domains, which can themselves contain nested subdomains. A forest is the security boundary within which all objects are under administrative control. A forest may contain multiple domains, and a domain may contain further child or sub-domains. A domain is a structure within which contained objects (users, computers, and groups) are accessible. Objects are the most basic unit of data in AD.

It contains many built-in **Organizational Units (OUs)**, such as “Domain Controllers,” “Users,” and “Computers,” and new OUs can be created as required. OUs may contain objects and sub-OUs, allowing for assignment of different group policies.

![image](https://github.com/user-attachments/assets/75a574a8-2628-43ed-a04d-1180c650694b)

We can see this structure graphically by opening Active Directory Users and Computers on a Domain Controller. In our lab domain INLANEFREIGHT.LOCAL, we see various OUs such as Admin, Employees, Servers, Workstations, etc. Many of these OUs have OUs nested within them, such as the Mail Room OU under Employees. This helps maintain a clear and coherent structure within Active Directory, which is especially important as we add Group Policy Objects (GPOs) to enforce settings throughout the domain.

![image](https://github.com/user-attachments/assets/b53092a2-3ee0-4b3e-bd30-5a99f72095a7)

# Rights and Privileges in AD

| Group                      | Description                                                                                                                                                                                                                                                                                                                   |
|----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Default Administrators     | Domain Admins and Enterprise Admins "super" groups.                                                                                                                                                                                                                                                                           |
| Server Operators           | Members can modify services, access SMB shares, and backup files.                                                                                                                                                                                                                                                             |
| Backup Operators           | Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs.                           |
| Print Operators            | Members are allowed to logon to DCs locally and "trick" Windows into loading a malicious driver.                                                                                                                                                                                                                               |
| Hyper-V Administrators     | If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.                                                                                                                                                                                            |
| Account Operators          | Members can modify non-protected accounts and groups in the domain.                                                                                                                                                                                                                                                           |
| Remote Desktop Users       | Members are not given any useful permissions by default but are often granted additional rights such as Allow Login Through Remote Desktop Services and can move laterally using the RDP protocol.                                                                                                                            |
| Remote Management Users    | Members are allowed to logon to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs).                                                                                                                                                                                           |
| Group Policy Creator Owners | Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU.                                                                                                                                                                                          |
| Schema Admins              | Members can modify the Active Directory schema structure and can backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL.                                                                                                                                                              |
| DNS Admins                 | Members have the ability to load a DLL on a DC but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to create a WPAD record. |

Reference: https://web.archive.org/web/20230129100526/https://cube0x0.github.io/Pocing-Beyond-DA/

- **Members of "Schema Admins" Group**
```
Get-ADGroup -Identity "Schema Admins" -Properties *
```

## User Rights Assignment

Typing the command `whoami /priv` will give you a listing of all user rights assigned to your current user. Some rights are only available to administrative users and can only be listed/leveraged when running an elevated cmd or PowerShell session. These concepts of elevated rights and User Account Control (UAC) are security features introduced with Windows Vista to default to restricting applications from running with full permissions unless absolutely necessary. If we compare and contrast the rights available to us as an admin in a non-elevated console vs. an elevated console, we will see that they differ drastically.

User rights increase based on the groups they are placed in and/or their assigned privileges.

## Microsoft Remote Server Administration Tools (RSAT)

The Remote Server Administration Tools (RSAT) have been part of Windows since the days of Windows 2000. RSAT allows systems administrators to remotely manage Windows Server roles and features from a workstation running Windows 10, Windows 8.1, Windows 7, or Windows Vista. RSAT can only be installed on Professional or Enterprise editions of Windows. In an enterprise environment, RSAT can remotely manage Active Directory, DNS, and DHCP. RSAT also allows us to manage installed server roles and features, File Services, and Hyper-V.

- **PowerShell - Available RSAT Tools**
```
Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property Name, State
```

- **PowerShell - Install All Available RSAT Tools**
```
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability –Online
```

- **PowerShell - Install an RSAT Tool**
```
Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0  –Online
```

Once installed, all of the tools will be available under **Administrative Tools** in the **Control Panel**.

![image](https://github.com/user-attachments/assets/a4524f54-cf93-4e26-bf01-b4ee4b25750e)

## Domain Context for Enumeration

Many tools are missing credential and context parameters and instead get those values directly from the current context. There are a few ways to alter a user's context in Windows if you have access to a password or a hash, such as:

Using "`runas /netonly`" to leverage the built-in `runas.exe` command line tool.

- **CMD - Runas User**
```
runas /netonly /user:htb.local\jackie.may powershell
```

Other tools that we will discuss in later modules, such as Rubeus and mimikatz can be passed cleartext credentials or an NTLM password hash.

- **CMD - Rubeus.exe Cleartext Credentials**
```
rubeus.exe asktgt /user:jackie.may /domain:htb.local /dc:10.10.110.100 /rc4:ad11e823e1638def97afa7cb08156a94
```

- **CMD - Mimikatz.exe Cleartext Credentials**
```
mimikatz.exe sekurlsa::pth /domain:htb.local /user:jackie.may /rc4:ad11e823e1638def97afa7cb08156a94
```

## Enumeration with RSAT

If we compromise a domain-joined system (or a client has you perform an AD assessment from one of their workstations), we can leverage RSAT to enumerate AD. While RSAT will make GUI tools such as **Active Directory Users and Computers** and **ADSI Edit** available to us, the most important tool we have seen throughout this module is the **PowerShell Active Directory module**.

Alternatively, we can enumerate the domain from a non-domain joined host (provided that it is in a subnet that communicates with a domain controller) by launching any RSAT snap-ins using "`runas`" from the command line. This is particularly useful if we find ourselves performing an internal assessment, gain valid AD credentials, and would like to perform enumeration from a Windows VM.

![image](https://github.com/user-attachments/assets/e24ecb1f-62d2-4338-a74e-50cb13c386b1)

We can also open the **MMC Console** from a non-domain joined computer using the following command syntax:

- **CMD - MMC Runas Domain User**
```
runas /netonly /user:Domain_Name\Domain_USER mmc
```

![image](https://github.com/user-attachments/assets/cbf33be4-8392-4a7f-8f46-0dbee9ba3fbf)

We can add any of the RSAT snap-ins and enumerate the target domain in the context of the target user `sally.jones` in the `freightlogistics.local` domain. After adding the snap-ins, we will get an error message that the "specified domain either does not exist or could not be contacted." From here, we have to right-click on the `Active Directory Users and Computers` snap-in (or any other chosen snap-in) and choose `Change Domain`.

![image](https://github.com/user-attachments/assets/dec5edc9-6191-4b3b-8116-1f6956e7a830)

Type the target domain into the `Change domain` dialogue box, here `freightlogistics.local`. From here, we can now freely enumerate the domain using any of the AD RSAT snapins.

![image](https://github.com/user-attachments/assets/ea6793fb-3333-4a23-aba9-9449d0df9ad6)

While these graphical tools are useful and easy to use, they are very inefficient when trying to enumerate a large domain. In the next few sections, we will introduce LDAP and various types of search filters that we can use to enumerate AD using PowerShell. The topics that we cover in these sections will help us gain a better understanding of how AD works and how to search for information efficiently, which will ultimately better inform us on the usage of the more "automated" tools and scripts that we will cover in the next two AD Enumeration modules.

# The Power of NT AUTHORITY\SYSTEM

The LocalSystem account `NT AUTHORITY\SYSTEM` is a built-in account in Windows operating systems, used by the service control manager. It has the highest level of access in the OS (and can be made even more powerful with Trusted Installer privileges). This account has more privileges than a local administrator account and is used to run most Windows services. It is also very common for third-party services to run in the context of this account by default.

The SYSTEM account on a domain-joined host can enumerate Active Directory **by impersonating the computer account**, which is essentially a special user account. If you land on a domain-joined host with **`SYSTEM`** privileges during an assessment and cannot find any useful credentials in memory or other data on the machine, there are still many things you can do. Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account. The only real limitation is not being able to perform cross-trust Kerberos attacks such as Kerberoasting.

There are several ways to gain `SYSTEM`-level access on a host, including but not limited to:
- Remote Windows exploits such as EternalBlue or BlueKeep.
- Abusing a service running in the context of the SYSTEM account.
- Abusing SeImpersonate privileges using RottenPotatoNG against older Windows systems, Juicy Potato, or PrintSpoofer if targeting Windows 10/Windows Server 2019.
- Local privilege escalation flaws in Windows operating systems such as the Windows 10 Task Scheduler 0day.
- PsExec with the `-s` flag

By gaining SYSTEM-level access on a domain-joined host, we will be able to:
- Enumerate the domain and gather data such as information about domain users and groups, local administrator access, domain trusts, ACLs, user and computer properties, etc., using `BloodHound`, and `PowerView`/`SharpView`.
- Perform Kerberoasting / ASREPRoasting attacks.
- Run tools such as Inveigh to gather Net-NTLM-v2 hashes or perform relay attacks.
- Perform token impersonation to hijack a privileged domain user account.
- Carry out ACL attacks.

- Reference: https://github.com/breenmachine/RottenPotatoNG
- Reference: https://github.com/ohpe/juicy-potato
- Reference: https://github.com/itm4n/PrintSpoofer
- Reference: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
- Reference: https://blog.0patch.com/2019/06/another-task-scheduler-0day-another.html
