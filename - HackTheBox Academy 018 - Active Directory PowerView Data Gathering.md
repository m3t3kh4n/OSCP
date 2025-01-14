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
















