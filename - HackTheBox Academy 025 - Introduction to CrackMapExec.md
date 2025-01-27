# Introduction to CrackMapExec

Documentation: https://wiki.porchetta.industries/

Some of the developers who contributed to the tool decided to create a fork to continue the project. The project was renamed to NetExec and is at https://github.com/Pennyw0rth/NetExec.

Reference: https://github.com/Pennyw0rth/NetExec

## Targets and Protocols
Depending on the scope, we can scan one or more targets within a specific range or predefined hostnames during an engagement. CrackMapExec can handle that perfectly. The target can be a CIDR, one IP, a hostname, or a file name containing the IP addresses/hostnames.

```
m3t3kh4n@htb[/htb]$ crackmapexec [protocol] 10.10.10.1
m3t3kh4n@htb[/htb]$ crackmapexec [protocol] 10.10.10.1 10.10.10.2 10.10.10.3
m3t3kh4n@htb[/htb]$ crackmapexec [protocol] 10.10.10.1/24
m3t3kh4n@htb[/htb]$ crackmapexec [protocol] internal.local
m3t3kh4n@htb[/htb]$ crackmapexec [protocol] targets.txt
```

## Supported Protocols

Protocol	Default Port
- SMB	445
- WINRM	5985/5986
- MSSQL	1433
- LDAP	389
- SSH	22
- RDP	3389
- FTP	21

We can run `crackmapexec <protocol> --help` to view the options a specified protocol supports. Let's see LDAP as an example:

- **Password Spray Example with WinRm**
```
m3t3kh4n@htb[/htb]$ crackmapexec winrm 10.10.10.1 -u users.txt -p password.txt --no-bruteforce --continue-on-success
```

> If we want to perform a password spraying attack against any other protocol, we need to modify the protocol and that's it.

## Export Function

```
m3t3kh4n@htb[/htb]$ crackmapexec smb 10.10.10.1 [protocol options] --export $(pwd)/export.txt
```

## Protocol Modules

CrackMapExec supports modules, which we will use and discuss later. Each protocol has different modules. We can run `crackmapexec <protocol> -L` to view available modules for the specified protocol.

```
--ntds
--local-auth
```
