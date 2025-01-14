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
















