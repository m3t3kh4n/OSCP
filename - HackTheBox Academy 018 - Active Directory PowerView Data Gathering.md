# Data Gathering

# Enumerating AD Users

We can start by getting a count of how many users are in the target domain.
```
(Get-DomainUser).count
```

Next, let's explore the `Get-DomainUser` function. If we provide the `-Help` flag to any `SharpView` function, we can see all of the parameters that the function accepts.
```
.\SharpView.exe Get-DomainUser -Help
```
Below are some of the most important properties to gather about domain users. Let's take a look at the harry.jones user.
```
Get-DomainUser -Identity harry.jones -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,mail,useraccountcontrol
```
It is useful to enumerate these properties for ALL domain users and export them to a CSV file for offline processing.
```
Get-DomainUser * -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,mail,useraccountcontrol | Export-Csv .\inlanefreight_users.csv -NoTypeInformation
```
Once we have gathered information on all users, we can begin to perform more specific user enumeration by obtaining a list of users that do not require Kerberos pre-authentication and can be subjected to an ASREPRoast attack.
```
.\SharpView.exe Get-DomainUser -KerberosPreauthNotRequired -Properties samaccountname,useraccountcontrol,memberof
```
Let's also gather information about users with Kerberos constrained delegation.
```
.\SharpView.exe Get-DomainUser -TrustedToAuth -Properties samaccountname,useraccountcontrol,memberof
```
While we're at it, we can look for users that allow unconstrained delegation.
```
.\SharpView.exe Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
```
We can also check for any domain users with sensitive data such as a password stored in the description field.
```
Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}
```
Next, let's enumerate any users with Service Principal Names (SPNs) that could be subjected to a Kerberoasting attack.
```
.\SharpView.exe Get-DomainUser -SPN -Properties samaccountname,memberof,serviceprincipalname
```
Finally, we can enumerate any users from other (foreign) domains with group membership within any groups in our current domain. We can see that the user harry.jones from the FREIGHTLOGISTICS.LOCAL domain is in our current domain's administrators group. If we compromise the current domain, we may obtain credentials for this user from the NTDS database and authenticate into the FREIGHTLOGISTICS.LOCAL domain.
```
Find-ForeignGroup
```
```
Convert-SidToName S-1-5-21-888139820-103978830-333442103-1602
```
Another useful command is checking for users with Service Principal Names (SPNs) set in other domains that we can authenticate into via inbound or bi-directional trust relationships with forest-wide authentication allowing all users to authenticate across a trust or selective-authentication set up which allows specific users to authenticate. Here we can see one account in the FREIGHTLOGISTICS.LOCAL domain, which could be leveraged to Kerberoast across the forest trust.
```
Get-DomainUser -SPN -Domain freightlogistics.local | select samaccountname,memberof,serviceprincipalname | fl
```
### Password Set Times
Analyzing the Password Set times is incredibly important when performing password sprays. Organizations are much more likely to find an automated password spray across all accounts than at a few guesses towards a small group of accounts.
- If you see a **several passwords set at the same time**, this indicates they were set by the Help Desk and may be the same. Because of Password Lockout Policies, you may not be able to exceed four failed passwords in fifteen minutes. However, if you think the password is the same across 20 accounts, for one user, you can guess passwords along the line of "Password2020" for a different use, you can use the company name like "Freight2020!".
- Additionally, if you see the password was set in July of 2019; then you can normally exclude "2020" from your password guessing and probably shouldn't guess variations that wouldn't make sense, such as "Winter2019."
- If you see an old password that was set 2 years ago, chances are this password is weak and also one of the first accounts I would recommend guessing the password to before launching a large Password Spray.
- In most organizations, administrators have multiple accounts. If you see the administrator changing his "user account" around the same time as his "Administrator Account", they are highly likely to use the same password for both accounts.

The following command will display all password set times.
```
Get-DomainUser -Properties samaccountname,pwdlastset,lastlogon -Domain InlaneFreight.local | select samaccountname, pwdlastset, lastlogon | Sort-Object -Property pwdlastset
```

If you want only to show passwords set before a certain date:
```
Get-DomainUser -Properties samaccountname,pwdlastset,lastlogon -Domain InlaneFreight.local | select samaccountname, pwdlastset, lastlogon | where { $_.pwdlastset -lt (Get-Date).addDays(-90) }
```

# Enumerating AD Groups
A quick check shows that our target domain, INLANEFREIGHT.LOCAL has 72 groups.
```
Get-DomainGroup -Properties Name
```
Let's grab a full listing of the group names. Many of these are built-in, standard AD groups. The presence of some group shows us that Microsoft Exchange is present in the environment. An Exchange installation adds several groups to AD, some of which such as **Exchange Trusted Subsystem** and **Exchange Windows Permissions** are considered _high-value targets_ due to the permissions that membership in these groups grants a user or computer. Other groups such as **Protected Users**, **LAPS Admins**, **Help Desk**, and **Security Operations** should be noted down for review.

Reference: https://github.com/gdedrouas/Exchange-AD-Privesc

We can use `Get-DomainGroupMember` to examine group membership in any given group. Again, when using the `SharpView` function for this, we can pass the `-Help` flag to see all of the parameters that this function accepts.
```
.\SharpView.exe Get-DomainGroupMember -Help
```
A quick examination of the `Help Desk` group shows us that there are two members.
```
.\SharpView.exe Get-DomainGroupMember -Identity 'Help Desk'
```
## Protected Groups
Next, we can look for all AD groups with the `AdminCount` attribute set to `1`, **signifying that this is a protected group**.
```
.\SharpView.exe Get-DomainGroup -AdminCount
```
Another important check is to look for any **managed security groups**. These groups have delegated non-administrators the right to add members to AD security groups and **distribution groups** and is set by modifying the **`managedBy`** attribute. This check looks to see if a group has a manager set and if the user can add users to the group. This could be useful for lateral movement by gaining us access to additional resources. First, let's take a look at the list of managed security groups.
```
Find-ManagedSecurityGroups | select GroupName
```
Next, let's look at the `Security Operations` group and see if the group has a manager set. We can see that the user `joe.evans` is set as the group manager.
```
Get-DomainManagedSecurityGroup
```
Enumerating the ACLs set on this group, we can see that this user has `GenericWrite` privileges meaning that this user can modify group membership (add or remove users). If we gain control of this user account, we can add this account or any other account that we control to the group and inherit any privileges that it has in the domain.
```
ConvertTo-SID joe.evans
$sid = ConvertTo-SID joe.evans
Get-DomainObjectAcl -Identity 'Security Operations' | ?{ $_.SecurityIdentifier -eq $sid}
```

## Local Groups
It is also important to check local group membership. Is our current user local admin or part of local groups on any hosts? We can get a list of the local groups on a host using `Get-NetLocalGroup`.
```
Get-NetLocalGroup -ComputerName WS01 | select GroupName
```
We can also enumerate the local group members on any given host using the `Get-NetLocalGroupMember` function.
```
.\SharpView.exe Get-NetLocalGroupMember -ComputerName WS01
```
We see one **non-RID 500 user** in the local administrators group and use the `Convert-SidToName` function to convert the SID and reveal the `harry.jones` user.

We use this same function to check all the hosts that a given user has local admin access, though this can be done much quicker with another PowerView/SharpView function that we will cover later in this module.

```
$sid = Convert-NameToSid harry.jones
$computers = Get-DomainComputer -Properties dnshostname | select -ExpandProperty dnshostname
foreach ($line in $computers) {Get-NetLocalGroupMember -ComputerName $line | ? {$_.SID -eq $sid}}
```

## Pulling Date User Added to Group
PowerView cannot pull the date when a user was added to a group, but since we are enumerating groups here, we wanted to include it. This information isn't too helpful for an attacker. Still, adding information that can aid in Incident Response will make your report stand out and hopefully lead to repeat business. Having this information, if you notice a strange user as part of a group, defenders can search for Event ID 4728/4738 on that date to find out who added the user, or Event ID 4624 since the date added to see if anyone has logged in.

The module we generally use to pull this information is called `Get-ADGroupMemberDate` and can be downloaded here. Load this module up the same way you would PowerView.

Reference: https://raw.githubusercontent.com/proxb/PowerShell_Scripts/master/Get-ADGroupMemberDate.ps1

Then run `Get-ADGroupMemberDate -Group "Help Desk" -DomainController DC01.INLANEFREIGHT.LOCAL`, if there is a specific user you want to pull, we recommend running `Get-ADGroupMemberDate -Group "Help Desk" -DomainController DC01.INLANEFREIGHT.LOCAL | ? { ($_.Username -match 'harry.jones') -And ($_.State -NotMatch 'ABSENT') }`.

```
Get-NetLocalGroupMember -GroupName "Remote Management Users" -ComputerName WS01
```

# Enumerating AD Computers

## Domain Computer Information

We can use the `Get-DomainComputer` function to enumerate many details about domain computers.
```
.\SharpView.exe Get-DomainComputer -Help
```
Some of the most useful information we can gather is the hostname, operating system, and User Account Control (UAC) attributes.
```
.\SharpView.exe Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp,useraccountcontrol
```
Let's save this data to a CSV for our records using PowerView.
```
Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp,useraccountcontrol | Export-Csv .\inlanefreight_computers.csv -NoTypeInformation
```

## Finding Exploitable Machines

The most obvious thing in the above screenshot is within the "User Account Control" setting, and we will get into that shortly. However, tools like Bloodhound will quickly point this setting out, and it may become uncommon to find in organizations that have regular penetration tests performed. The following flags can be combined to help come up with attacks:
- **`LastLogonTimeStamp`**: This field exists to let administrators find stale machines. If this field is 90 days old for a machine, it has not been turned on and is missing both operating system and application patches. Due to this, administrators may want to automatically disable machines upon this field hitting 90 days of age. Attackers can use this field in combination with other fields such as **Operating System** or **When Created** to identify targets.
- **`OperatingSystem`**: This lists the Operating System. The obvious attack path is to find a Windows 7 box that is still active (LastLogonTimeStamp) and try attacks like Eternal Blue. Even if Eternal Blue is not applicable, older versions of Windows are ideal spots to work from as there are fewer logging/antivirus capabilities on older Windows. It's also important to know the differences between flavors of Windows. For example, Windows 10 Enterprise is the only version that comes with "Credential Guard" (Prevents Mimikatz from Stealing Passwords) Enabled by default. If you see Administrators logging into Windows 10 Professional and Windows 10 Enterprise, the Professional box should be targeted.
- **`WhenCreated`**: This field is created when a machine joins Active Directory. The older the box is, the more likely it is to deviate from the "Standard Build." Old workstations could have weaker local administration passwords, more local admins, vulnerable software, more data, etc.

## Computer Attacks
We can see if any computers in the domain are configured to allow **unconstrained delegation** and find one, the domain controller, which is standard.

Reference: https://adsecurity.org/?p=1667

```
.\SharpView.exe Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol
```

Finally, we can check for any hosts set up to allow for **constrained delegation**.

Reference: https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview#:~:text=Constrained%20delegation%20gives%20service%20administrators,to%20their%20back%2Dend%20services.

```
Get-DomainComputer -TrustedToAuth | select -Property dnshostname,useraccountcontrol
```

# Enumerating Domain ACLs

## Access Control Lists (ACLs)

Access Control List (ACL) settings themselves are called Access Control Entries (ACEs). Each ACE refers back to a user, group, or process (security principal) and defines the principal's rights.

There are two types of ACLs.
- **Discretionary Access Control List (DACL)**	This defines which security principals are granted or denied access to an object.
- **System Access Control Lists (SACL)**	These allow administrators to log access attempts made to secured objects.

ACL (mis)-configurations may allow for chained object-to-object control. We can visualize unrolled membership of target groups, so-called **derivative admins**, who can derive admin rights from exploiting an AD attack chain.

AD Attack chains may include the following components:
- "Unprivileged" users (shadow admins) having administrative access on member servers or workstations.
- Privileged users having a logon session on these workstations and member servers.
- Other forms of object-to-object control include force password change, add group member, change owner, write ACE, and full control.

Below is an example of just some of the ACLs that can be set on a user object.
![image](https://github.com/user-attachments/assets/617d1783-e196-4dea-8ef1-c4de05f68c51)

## ACL Abuse

Why do we care about ACLs? ACL abuse is a powerful attack vector for us as penetration testers. These types of misconfigurations often go unnoticed in corporate environments because they can be difficult to monitor and control. An organization may be unaware of overly permissive ACL settings for years before (hopefully) we discover them. Below are some of the example Active Directory object security permissions (supported by `BloodHound` and abusable with `SharpView`/`PowerView`):

- **`ForceChangePassword`** abused with `Set-DomainUserPassword`
- **`Add Members`** abused with `Add-DomainGroupMember`
- **`GenericAll`** abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- **`GenericWrite`** abused with `Set-DomainObject`
- **`WriteOwner`** abused with `Set-DomainObjectOwner`
- **`WriteDACL`** abused with `Add-DomainObjectACL`
- **`AllExtendedRights`** abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`

## Enumerating ACLs with Built-In Cmdlets

We can use the built-in `Get-ADUser` cmdlet to enumerate ACLs. For example, we can look at the ACL for a single domain user `daniel.carter` with this command.
```
(Get-ACL "AD:$((Get-ADUser daniel.carter).distinguishedname)").access  | ? {$_.IdentityReference -eq "INLANEFREIGHT\cliff.moore"}
```
We can drill down further on this user to find all users with `WriteProperty` or `GenericAll` rights over the target user.
```
(Get-ACL "AD:$((Get-ADUser daniel.carter).distinguishedname)").access  | ? {$_.ActiveDirectoryRights -match "WriteProperty" -or $_.ActiveDirectoryRights -match "GenericAll"} | Select IdentityReference,ActiveDirectoryRights -Unique | ft -W
```

## Enumerating ACLs with PowerView and SharpView

We can use `PowerView`/`SharpView` to perform the previous command much quicker. For example, `Get-DomainObjectACL` can be used on a user to return similar data.
```
Get-DomainObjectAcl -Identity harry.jones -Domain inlanefreight.local -ResolveGUIDs
```
We can seek out ACLs on specific users and filter out results using the various AD filters covered in the Active Directory LDAP module. We can use the `Find-InterestingDomainAcl` to search out objects in the domain with modification rights over non-built-in objects. This command, too, produces a large amount of data and can either be filtered on for information about specific objects or saved to be examined offline.
```
Find-InterestingDomainAcl -Domain inlanefreight.local -ResolveGUIDs
```
Aside from users and computers, we should also look at the ACLs set on **file shares**. This could provide us with information about which users can access a specific share or permissions are set too loosely on a specific share, which could lead to sensitive data disclosure or other attacks.
```
Get-NetShare -ComputerName SQL01
Get-PathAcl "\\SQL01\DB_backups"
```

Aside from ACLs of specific users and computers that may allow us to fully control or grant us other permissions, we should also check the ACL of the domain object. A common attack called **DCSync** requires a user to be delegated a combination of the following three rights:

- **Replicating Directory Changes** (**`DS-Replication-Get-Changes`**)
- **Replicating Directory Changes All** (**`DS-Replication-Get-Changes-All`**)
- **Replicating Directory Changes In Filtered Set** (**`DS-Replication-Get-Changes-In-Filtered-Set`**)

We can use the `Get-ObjectACL` function to search for all users that have these rights.

```
Get-ObjectACL "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object SecurityIdentifier | Sort-Object -Property SecurityIdentifier -Unique
```
Once we have the `SIDs` we can convert the SID back to the user to see which accounts have these rights and determine whether or not this is intended and/or if we can abuse these rights.
```
convertfrom-sid S-1-5-21-2974783224-3764228556-2640795941-1883
```
This can be done quickly to enumerate all users with this right.
```
$dcsync = Get-ObjectACL "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value

Convert-SidToName $dcsync
```

## Leveraging ACLs

As seen in this section, various ACE entries can be set within AD. Administrators may set some on purpose to grant fine-grained privileges over an object or set of objects. In contrast, others may result from misconfigurations or installation of a service such as Exchange, which makes many changes ACLs within the domain by default.

We may compromise a user with `GenericWrite` over a user or group and can leverage this to force change a user's password or add our account to a specific group to further our access. Any modifications such as these should be carefully noted down and mentioned in the final report so the client can make sure changes are reverted if we cannot during the assessment period. Also, a "destructive" action, such as changing a user's password, should be used sparingly and coordinated with the client to avoid disruptions.

If we find a user, group, or computer with **`WriteDacl`** privileges over an object, we can leverage this in several ways. For example, if we can compromise a member of an Exchange-related group such as **Exchange Trusted Subsystem** we will likely have **`WriteDacl`** privileges over the domain object itself and be able to grant an account we control **`Replicating Directory Changes`** and **`Replicating Directory Change`** permissions to an account that we control and perform a DCSync attack to fully compromise the domain by mimicking a Domain Controller to retrieve user NTLM password hashes for any account we choose.
``
If we find ourselves with **`GenericAll`**/**`GenericWrite`** privileges over a target user, a less destructive attack would be to set a fake `SPN` on the account and perform a targeted **Kerberoasting** attack or modify the account's `userAccountControl` not to require Kerberos pre-authentication and perform a targeted **ASREPRoasting** attack. These examples require the account to be using a weak password that can be cracked offline using a tool such as `Hashcat` with minimal effort but are much less destructive than changing a user's password and have a higher likelihood of going unnoticed.

If you perform a destructive action such as changing a user's password and can compromise the domain, you can **DCSync**, obtain the account's password history, and use Mimikatz to reset the account to the previous password using **`LSADUMP::ChangeNTLM`** or **`LSADUMP::SetNTLM`**.

If we find ourselves with **`GenericAll`**/**`GenericWrite`** on a computer, we can perform a **Kerberos Resource-based Constrained Delegation** attack.

Sometimes we will find that a user or even the entire `Domain Users` group has been granted write permissions over a specific group policy object. If we find this type of misconfiguration, and the GPO is linked to one or more users or computers, we can use a tool such as **`SharpGPOAbuse`** to modify the target GPO to perform actions such as provisioning additional privileges to a user (such as **`SeDebugPrivilege`** to be able to perform targeted credential theft, or **`SeTakeOwnershipPrivilege`** to gain control over a sensitive file or file share), add a user we control as a local admin to a target host, add a computer startup script, and more. As discussed above, these modifications should be performed carefully in coordination with the client and noted in the final report to minimize disruptions.

This is a summary of the many options we have for abusing ACLs. This topic will be covered more in-depth in later modules.

Reference: https://github.com/FSecureLABS/SharpGPOAbuse

# Enumerating Group Policy Objects (GPOs)

Group Policy provides systems administrators with a centralized way to manage configuration settings and manage operating systems and user and computer settings in a Windows environment. A Group Policy Object (GPO) is a collection of policy settings. GPOs include policies such as screen lock timeout, disabling USB ports, domain password policy, push out software, manage applications, and more. GPOs can be applied to individual users and hosts or groups by being applied directly to an Organizational Unit (OU). Gaining rights over a GPO can lead to lateral vertical movement up to full domain compromise and can also be used as a persistence mechanism. Like ACLs, GPOs are often overlooked, and one misconfigured GPO can have catastrophic results.

We can use `Powerview`/`Sharpview`, `BloodHound`, and `Group3r` to enumerate Group Policy security misconfigurations. This section will show some of the enumeration techniques we can perform on the command line using PowerView and SharpView.

## GPO Abuse

GPOs can be abused to perform attacks such as adding additional rights to a user, adding a local admin, or creating an immediate scheduled task. There are several ways to gain persistence via GPOs:
- Configure a GPO to run any of the above attacks.
- Create a scheduled task to modify group membership, add an account, run DCSync, or send back a reverse shell connection.
- Install targeted malware across the entire Domain.

`SharpGPOAbuse` is an excellent tool that can be used to take advantage of GPO misconfigurations. This section will help arm us with the data that we need to use tools such as this.

Reference: https://github.com/FSecureLABS/SharpGPOAbuse

## Gathering GPO Data
Let's start by gathering GPO names. In our test domain INLANEFREIGHT.LOCAL, there are 20 GPOs applied to various OUs.
```
Get-DomainGPO | select displayname
```
We can also check which GPOs apply to a specific computer.
```
Get-DomainGPO -ComputerName WS01 | select displayname
```
Analyzing the GPO names can give us an idea of some of the security configurations in the target domain, such as LAPS, AppLocker, PowerShell Logging, cmd.exe disabled for workstations, etc. We can check for hosts/users that these GPOs are not applied to and plan out our attack paths for circumventing these controls.

If we do not have tools available to us, we can use **`gpresult`**, which is a built-in tool that determines GPOs that have been applied to a given user or computer and their settings. We can use specific commands to see the GPOs applied to a specific user and computer, respectively, such as:
```
gpresult /r /user:harry.jones
```

```
gpresult /r /S WS01
```

The tool can output in HTML format with a command such as **`gpresult /h gpo_report.html`**.

Let's use `gpresult` to see what GPOs are applied to a workstation in the domain.

```
gpresult /r /S WS01
```

## GPO Permissions
After reviewing all of the GPOs applied throughout the domain, it is always good to look at GPO permissions. We can use the `Get-DomainGPO` and `Get-ObjectAcl` using the **SID for the Domain Users group** to see if this group has any permissions assigned to any GPOs.

```
Get-DomainGPO | Get-ObjectAcl | ? {$_.SecurityIdentifier -eq 'S-1-5-21-2974783224-3764228556-2640795941-513'}
```

From the result, we can see that one GPO allows all Domain Users full write access. We can then confirm the name of the GPO using the built-in cmdlet `Get-GPO`.

```
Get-GPO -Guid 831DE3ED-40B1-4703-ABA7-8EA13B2EB118
```
This misconfigured GPO could be exploited using a tool such as **`SharpGPOAbuse`** and the **`--AddUserRights`** attack to give a user unintended rights or the **`--AddLocalAdmin`** attack to add a user as a local admin on a machine where the GPO is applied and use it to move laterally towards our target.

## Hidden GPO Code Execution Paths

Group Policy is the most basic way System Administrators can command many Computers to perform a task. It is not the most common way to do things as many organizations will use commercial applications such as:

- Microsoft SCCM - System Center Configuration Manager
- PDQInventory/Deploy
- NinjaRMM (Remote Management and Monitoring)
- Ansible/Puppet/Salt

However, each one of these applications is non-default, and when an Administrator googles for a solution, their answer probably won't include the technology they use. Often, you may find one-off configurations an administrator did to accomplish a task quickly. For example, on multiple occasions, I have run across a "Machine/User Startup" script to collect inventory and write it to a domain share. I have seen this policy execute both BAT and VBScript files that were either write-able by the machine account or domain users. Whenever I dig into file shares and see files write-able by Everyone, Authenticated Users, Domain Users, Domain Computers, etc., containing what looks like log files, I dig into Group Policy, specifically looking for Startup Scripts.

That is just one way an Administrators use "Code Execution via GP" legitimately. Here is a list of the path's I know about:

- Add Registry Autoruns
- Software Installation (Install MSI Package that exists on a share)
- Scripts in the Startup/Shutdown for a Machine or User
- Create Shortcuts on Desktops that point to files
- Scheduled Tasks

If anyone of these paths points to a file on a share, enumerate the permissions to check if non-administrators can edit the file. Your tools will often miss this because it only looks at if the Group Policy itself is write-able, not if the executables/scripts the group policy references are writeable.

# Enumerating AD Trusts

A trust is used to establish forest-forest or domain-domain authentication, allowing users to access resources in (or administer) another domain outside of the domain their account resides in.

_A trust creates a link between the authentication systems of two domains._

Trusts can be transitive or non-transitive.
- A transitive trust means that trust is extended to objects which the child domain trusts.
- In a non-transitive trust, only the child domain itself is trusted.

Trusts can be set up to be one-way or two-way (bidirectional).
- In bidirectional trusts, users from both trusting domains can access resources.
- In a one-way trust, only users in a trusted domain can access resources in a trusting domain, not vice-versa. The direction of trust is opposite to the direction of access.

There are several trust types.
- Parent-child	Domains within the same forest. The child domain has a two-way transitive trust with the parent domain.
- Cross-link	A trust between child domains to speed up authentication.
- External	A non-transitive trust between two separate domains in separate forests that are not already joined by a forest trust. This type of trust utilizes SID filtering.
- Tree-root	A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
- Forest	A transitive trust between two forest root domains.

Often, domain trusts are set up improperly and provide unintended attack paths. Also, trusts set up for ease of use may not be reviewed later for potential security implications. M&A can result in bidirectional trusts with acquired companies, unknowingly introducing risk into the acquiring company’s environment. It is not uncommon to perform an attack such as Kerberoasting against a domain outside the principal domain and obtain a user with administrative access within the principal domain.

## Enumerating Trust Relationships

Aside from using built-in AD tools such as the Active Directory PowerShell module, `PowerView`/`SharpView` and `BloodHound` can be utilized to enumerate trust relationships, the type of trusts established, as well as the authentication flow.

`BloodHound` creates a graphical view of trust relationships, which helps both attackers and defenders understand potential trust-related vectors.

`PowerView` can be used to perform a domain trust mapping and provide information such as the type of trust (parent/child, external, forest), as well as the direction of the trust (one-way or bidirectional). All of this information is extremely useful once a foothold is obtained, and you are planning to compromise the environment further.

We can use the function `Get-DomainTrust` to quickly check which trusts exist, the type, and the direction of the trusts.
```
Get-DomainTrust
```
We can use the function `Get-DomainTrustMapping` to enumerate all trusts for our current domain and other reachable domains.
```
Get-DomainTrustMapping
```
Depending on the trust type, there are several attacks that we may be able to perform, such as the **ExtraSids** attack to compromise a parent domain once the child domain has been compromised or cross-forest trust attacks such as **Kerberoasting** and **ASREPRoasting** and **SID History abuse**. Each of these attacks will be covered in-depth in later modules.

## Attacking Trusts

Organizations set up a trust for various reasons, i.e., ease of management, quickly "plugging in" a new forest obtained through a merger & acquisition, enabling communications between multiple branches of a company, etc. Managed service providers often set up trusts between their domain and those of their clients to facilitate administration.

Some examples for why an organization may set up a trust are:
- Keeping management local to regions. You may see FLORIDA.INLANEFREIGHT.LOCAL. By having the FLORIDA Domain, it is easy for administrators to ensure those users access resources in their LAN.
- Acquisitions - When a company acquires another company and wants a quick way to manage the new equipment without rebuilding anything. They may establish a trust. This can lead to issues, especially if the acquired company has not had regular security assessments performed, has legacy hosts in its environment, has different/no security monitoring controls in place, etc.
- Keeping development, testing, etc., logically separated. If DEVELOPMENT.INLANEFREIGHT.LOCAL has little privileges over INLANEFREIGHT.LOCAL, it is unlikely for beta code to have any adverse effects on production.

In all of these cases, Domain Trusts are set up to minimize the number of accounts required. It is much easier to manage multiple domains when you can reference adjacent domains' groups/users. If configured wrong, with lax permissions, etc., a trust relationship can be attacked to further our access, compromising one or many domains in the process.

In our example environment, the domain INLANEFREIGHT.LOCAL has a bidirectional trust with the LOGISTICS.INLANEFREIGHT.LOCAL domain and is set up as a parent-child trust relationship (both domains within the same forest with INLANEFREIGHT.LOCAL acting as the forest root domain.). If we can gain a foothold in either domain, we will be able to perform attacks such as Kerberoasting or ASREPRoasting across the trust in either direction because our compromised user would be able to authenticate to/from the parent domain, therefore querying any AD objects in the other domain.

Furthermore, if we can compromise the child domain LOGISTICS.INLANEFREIGHT.LOCAL we will be able to compromise the parent domain using the **ExtraSids** attack. This is possible because the `sidHistory` property is respected due to a lack of "SID Filtering" protection. Therefore, a user in a child domain with their sidHistory set to the Enterprise Admins group (which only exists in the parent domain) is treated as a member of this group, which allows for administrative access to the entire forest.

Our lab environment also shows a bidirectional forest trust between the INLANEFREIGHT.LOCAL and freightlogistics.local forests, meaning that users from either forest can authenticate across the trust and query any AD object within the partner forest. Aside from attacks such as **Kerberoasting** and **ASREPRoasting**, we may also be able to abuse **SID History** to compromise the trusting forest.

The SID history attribute is used in migration scenarios. If a user in one domain is migrated to another domain, a new account is created in the second domain. The original user's SID will be added to the new user's SID history attribute, ensuring that they can still access resources in the original domain.

SID history is intended to work across domains but can actually work in the same domain. Using `Mimikatz`, it is possible to perform SID history injection and add an administrator account to the SID History attribute of an account that they control. When logging in with this account, all of the SIDs associated with the account are added to the user's token.

This token is used to determine what resources the account can access. If the SID of a Domain Admin account is added to the SID History attribute of this account, this account will be able to perform DCSync and create golden tickets for further persistence.

This can also be abused across a forest trust. If a user is migrated from one forest to another and SID Filtering is not enabled, it becomes possible to add a SID from the other forest, and this SID will be added to the user's token when authenticating across the trust. If the SID of an account having administrative privileges in Forest A is added to the SID history attribute of an account in Forest B, assuming they can authenticate across the forest, this account will have administrative privileges when accessing resources in the partner forest.

Another common way to cross trust boundaries is by leveraging password re-use. Let's say we compromise the INLANEFREIGHT.LOCAL forest and find a user account named BSIMMONS_ADM that also exists in the freightlogistics.local forest. There is a good chance that this administrator re-uses their password across environments. Also, it is always worth checking for foreign users/foreign group membership. We may find accounts belonging to administrative (or non-administrative) groups in Forest A that are actually part of Forest B and can be used to gain a foothold in the partner forest.

Each of these attacks will be covered in-depth in later modules.
