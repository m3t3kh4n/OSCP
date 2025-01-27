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


















