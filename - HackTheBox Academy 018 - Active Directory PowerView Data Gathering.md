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






















