# Windows Privilege Escallation

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
