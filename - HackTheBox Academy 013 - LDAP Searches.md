# LDAP Overview

Lightweight Directory Access Protocol (LDAP) is an integral part of Active Directory (AD). The latest LDAP specification is Version 3

LDAP is an open-source and cross-platform protocol used for authentication against various directory services (such as AD). As discussed in the previous section, AD stores user account information and security information such as passwords and facilitates sharing this information with other devices on the network. LDAP is the language that applications use to communicate with other servers that also provide directory services. In other words, LDAP is a way that systems in the network environment can "speak" to AD.

An LDAP session begins by first connecting to an LDAP server, also known as a **Directory System Agent**. The Domain Controller in AD actively listens for LDAP requests, such as security authentication requests.

![image](https://github.com/user-attachments/assets/f64e4546-dc8a-477c-a785-d84408b3e7f6)

The relationship between AD and LDAP can be compared to Apache and HTTP. The same way Apache is a web server that uses the HTTP protocol, Active Directory is a directory server that uses the LDAP protocol.

While uncommon, you may come across organizations while performing an assessment that does not have AD but does have LDAP, meaning that they most likely use another type of LDAP server such as **OpenLDAP**.

## AD LDAP Authentication
LDAP is set up to authenticate credentials against AD using a "`BIND`" operation to set the authentication state for an LDAP session. There are two types of LDAP authentication.
1. **Simple Authentication**: This includes anonymous authentication, unauthenticated authentication, and username/password authentication. Simple authentication means that a username and password create a BIND request to authenticate to the LDAP server.
2. **SASL Authentication**: The **Simple Authentication and Security Layer (SASL)** framework uses other authentication services, such as Kerberos, to bind to the LDAP server and then uses this authentication service (Kerberos in this example) to authenticate to LDAP. The LDAP server uses the LDAP protocol to send an LDAP message to the authorization service which initiates a series of challenge/response messages resulting in either successful or unsuccessful authentication. SASL can provide further security due to the separation of authentication methods from application protocols.

LDAP authentication messages are sent in cleartext by default so anyone can sniff out LDAP messages on the internal network. It is recommended to use TLS encryption or similar to safeguard this information in transit.

Reference: https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer

## LDAP Queries

We can communicate with the directory service using LDAP queries to ask the service for information. For example, the following query can be used to find all workstations in a network `(objectCategory=computer)` while this query can be used to find all domain controllers: `(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))`.

LDAP queries can be used to perform user-related searches, such as "`(&(objectCategory=person)(objectClass=user))`" which searches for all users, as well as group related searches such as "`(objectClass=group)`" which returns all groups. Here is one example of a simple query to find all AD groups using the "`Get-ADObject`" cmdlet and the "`LDAPFilter parameter`".

- **LDAP Query - User Related Search**
```
Get-ADObject -LDAPFilter '(objectClass=group)' | select name
```

We can also use LDAP queries to perform more detailed searches. This query searches the domain for all administratively disabled accounts.

- **LDAP Query - Detailed Search**
```
Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' -Properties * | select samaccountname,useraccountcontrol
```

More examples of basic and more advanced LDAP queries for AD can be found at the following links:

- LDAP queries related to AD computers: https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20Computer%20Related%20LDAP%20Query
- LDAP queries related to AD users: https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20User%20Related%20Searches
- LDAP queries related to AD groups: https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20Group%20Related%20Searches

# Active Directory Search Filters

## PowerShell Filters

Filters in PowerShell allow you to process piped output more efficiently and retrieve exactly the information you need from a command. Filters can be used to narrow down specific data in a large result or retrieve data that can then be piped to another command.

- **PowerShell - Filter Installed Software**
```
get-ciminstance win32_product | fl
```

The above command can provide considerable output. We can use the Filter parameter with the notlike operator to filter out all Microsoft software (which may be useful when enumerating a system for local privilege escalation vectors).

- **PowerShell - Filter Out Microsoft Software**
```
get-ciminstance win32_product -Filter "NOT Vendor like '%Microsoft%'" | fl
```

## Operators

The `Filter` operator requires at least one operator, which can help narrow down search results or reduce a large amount of command output to something more digestible. Filtering properly is important, especially when enumerating large environments and looking for very specific information in the command output. The following operators can be used with the Filter parameter:

| Filter             | Meaning                          |
|--------------------|----------------------------------|
| `-eq`             | Equal to                        |
| `-le`             | Less than or equal to           |
| `-ge`             | Greater than or equal to        |
| `-ne`             | Not equal to                    |
| `-lt`             | Less than                       |
| `-gt`             | Greater than                    |
| `-approx`         | Approximately equal to          |
| `-bor`            | Bitwise OR                      |
| `-band`           | Bitwise AND                     |
| `-recursivematch` | Recursive match                 |
| `-like`           | Like                            |
| `-notlike`        | Not like                        |
| `-and`            | Boolean AND                     |
| `-or`             | Boolean OR                      |
| `-not`            | Boolean NOT                     |

## Filter Examples: AD Object Properties

Filters can be wrapped in curly braces, single quotes, parentheses, or double-quotes. For example, the following simple search filter using Get-ADUser to find information about the user Sally Jones can be written as follows:

- **PowerShell - Filter Examples**
```
Get-ADUser -Filter "name -eq 'sally jones'"
Get-ADUser -Filter {name -eq 'sally jones'}
Get-ADUser -Filter 'name -eq "sally jones"'
```

As seen above, the property value (here, `sally jones`) can be wrapped in single or double-quotes. The asterisk (`*`) can be used as a wildcard when performing queries. The command `Get-ADUser -filter {name -like "joe*"}` using a wildcard would return all domain users whose name start with joe (joe, joel, etc.). When using filters, certain characters must be escaped:

| Character | Escaped As | Note                                                                                                                                                                    |
|-----------|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `“`       | `` `” ``   | Only needed if the data is enclosed in double quotes.                                                                                                                   |
| `‘`       | `\’`       | Only needed if the data is enclosed in single quotes.                                                                                                                   |
| `NUL`     | `\00`      | Standard LDAP escape sequence.                                                                                                                                           |
| `\`       | `\5c`      | Standard LDAP escape sequence.                                                                                                                                           |
| `*`       | `\2a`      | Escaped automatically, but only in `-eq` and `-ne` comparisons. Use `-like` and `-notlike` operators for wildcard comparison.                                            |
| `(`       | `/28`      | Escaped automatically.                                                                                                                                                   |
| `)`       | `/29`      | Escaped automatically.                                                                                                                                                   |
| `/`       | `/2f`      | Escaped automatically.                                                                                                                                                   |


Let's try out some of these filters to enumerate the INLANEFREIGHT.LOCAL domain. We can search all domain computers for interesting hostnames. SQL servers are a particularly juicy target on internal assessments. The below command searches all hosts in the domain using Get-ADComputer, filtering on the DNSHostName property that contains the word SQL.

- **PowerShell - Filter For SQL**
```
Get-ADComputer  -Filter "DNSHostName -like 'SQL*'"
```

Next, let's search for administrative groups. We can do this by filtering on the `adminCount` attribute. The group with this attribute set to `1` are protected by `AdminSDHolder` and known as protected groups. AdminSDHolder is owned by the Domain Admins group. It has the privileges to change the permissions of objects in Active Directory. As discussed above, we can pipe the filtered command output and select just the group names.

- **PowerShell - Filter Administrative Groups**
```
Get-ADGroup -Filter "adminCount -eq 1" | select Name
```

We can also combine filters. Let's search for all administrative users with the `DoesNotRequirePreAuth` attribute set, meaning that they can be `ASREPRoasted`. Here we are selecting all domain users and specifying two conditions with the -eq operator.

- **PowerShell - Filter Administrative Users**
```
Get-ADUser -Filter {adminCount -eq '1' -and DoesNotRequirePreAuth -eq 'True'}
```

Finally, let's see an example of combining filters and piping output multiple times to find our desired information. The following command can be used to find all administrative users with the "`servicePrincipalName`" attribute set, meaning that they can likely be subject to a `Kerberoasting` attack. This example applies the Filter parameter to find accounts with the `adminCount` attribute set to `1`, pipes this output to find all accounts with a Service Principal Name (SPN), and finally selects a few attributes about the accounts, including the account name, group membership, and the SPN.

- **PowerShell - Find Administrative Users with the ServicePrincipalName**
```
Get-ADUser -Filter "adminCount -eq '1'" -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName | fl
```

# LDAP Search Filters

## Basic LDAP Filter Syntax and Operators

The LDAPFilter parameter with the same cmdlets lets us use LDAP search filters when searching for information.

LDAP filters must have one or more criteria. If more than one criteria exist, they can be concatenated together using logical AND or OR operators. These operators are always placed in the front of the criteria (operands), which is also referred to as Polish Notation.

Reference: https://en.wikipedia.org/wiki/Polish_notation

Filter rules are enclosed in parentheses and can be grouped by surrounding the group in parentheses and using one of the following comparison operators:

| Operator | Function |
|----------|----------|
| `&`      | and      |
| `|`      | or       |
| `!`      | not      |

Some example `AND` and `OR` operations are as follows:

`AND` Operation:
- One criteria: `(& (..C1..) (..C2..))`
- More than two criteria: `(& (..C1..) (..C2..) (..C3..))`

`OR` Operation:
- One criteria: `(| (..C1..) (..C2..))`
- More than two criteria: `(| (..C1..) (..C2..) (..C3..))`

We can also have nested operations, for example "`(|(& (..C1..) (..C2..))(& (..C3..) (..C4..)))`" translates to "`(C1 AND C2) OR (C3 AND C4)`".


## Search Criteria

When writing an LDAP search filter, we need to specify a rule requirement for the LDAP attribute in question (i.e. "`(displayName=william)`"). The following rules can be used to specify our search criteria:

| Criteria            | Rule                | Example                                      |
|---------------------|---------------------|----------------------------------------------|
| Equal to            | `(attribute=123)`   | `(&(objectclass=user)(displayName=Smith))`   |
| Not equal to        | `(!(attribute=123))`| `(!objectClass=group)`                      |
| Present             | `(attribute=*)`     | `(department=*)`                            |
| Not present         | `(!(attribute=*))`  | `(!homeDirectory=*)`                        |
| Greater than        | `(attribute>=123)`  | `(maxStorage=100000)`                       |
| Less than           | `(attribute<=123)`  | `(maxStorage<=100000)`                      |
| Approximate match   | `(attribute~=123)`  | `(sAMAccountName~=Jason)`                   |
| Wildcards           | `(attribute=*A)`    | `(givenName=*Sam)`                          |

Reference: https://docs.bmc.com/docs/fpsc121/ldap-attributes-and-associated-fields-495323340.html

## Object Identifiers (OIDs)

We can also use matching rule **Object Identifiers (OIDs)** with LDAP filters as listed in this Search Filter Syntax document from Microsoft:

Reference: https://ldapwiki.com/wiki/Wiki.jsp?page=OID

Reference: https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax

| Matching Rule OID          | String Identifier            | Description                                                                                                      |
|----------------------------|------------------------------|------------------------------------------------------------------------------------------------------------------|
| `1.2.840.113556.1.4.803`   | `LDAP_MATCHING_RULE_BIT_AND` | A match is found only if all bits from the attribute match the value. This rule is equivalent to a bitwise AND operator. |
| `1.2.840.113556.1.4.804`   | `LDAP_MATCHING_RULE_BIT_OR`  | A match is found if any bits from the attribute match the value. This rule is equivalent to a bitwise OR operator.      |
| `1.2.840.113556.1.4.1941`  | `LDAP_MATCHING_RULE_IN_CHAIN`| This rule is limited to filters that apply to the DN. This is a special "extended" match operator that walks the chain of ancestry in objects all the way to the root until it finds a match. |

We can clarify the above OIDs with some examples. Let's take the following LDAP query:

```
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)) 
```

This query will return all administratively disabled user accounts, or `ACCOUNTDISABLE` (2). We can combine this query as an LDAP search filter with the "`Get-ADUser`" cmdlet against our target domain. The LDAP query can be shortened as follows:

Reference: https://ldapwiki.com/wiki/Wiki.jsp?page=ACCOUNTDISABLE

- **LDAP Query - Filter Disabled User Accounts**
```
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' | select name
```

Now let's look at an example of the extensible match rule "`1.2.840.113556.1.4.1941`". Consider the following query:
```
(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)
```

This matching rule will find all groups that the user `Harry Jones` `("CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL")` is a member of. Using this filter with the "`Get-ADGroup`" cmdlet gives us the following output:

- **LDAP Query - Find All Groups**
```
Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name
```

## Filter Types, Item Types & Escaped Characters

With LDAP search filters, we have the following four filter types:

Reference: https://ldapwiki.com/wiki/Wiki.jsp?page=LDAP%20SearchFilters

| Operator | Meaning                  |
|----------|--------------------------|
| `=`      | Equal to                |
| `~=`     | Approximately equal to  |
| `>=`     | Greater than or equal to |
| `<=`     | Less than or equal to    |

And we have four item types:

| Type             | Meaning                       |
|------------------|-------------------------------|
| `=`              | Simple                        |
| `=*`             | Present                       |
| `=something*`    | Substring                    |
| `Extensible`     | Varies depending on type      |

Finally, the following characters must be escaped if used in an LDAP filter:

| Character | Represented as Hex |
|-----------|---------------------|
| `*`       | `\2a`              |
| `(`       | `\28`              |
| `)`       | `\29`              |
| `\`       | `\5c`              |
| `NUL`     | `\00`              |


## Example LDAP Filters

Let's build a few more LDAP filters to use against our test domain.

We can use the filter "`(&(objectCategory=user)(description=*))`" to find all user accounts that do not have a blank description field. This is a useful search that should be performed on every internal network assessment as it not uncommon to find passwords for users stored in the user description attribute in AD (which can be read by all AD users).

Combining this with the "`Get-ADUser`" cmdlet, we can search for all domain users that do not have a blank description field and, in this case, find a service account password!

- **LDAP Query - Description Field**
```
Get-ADUser -Properties * -LDAPFilter '(&(objectCategory=user)(description=*))' | select samaccountname,description
```
This filter "`(userAccountControl:1.2.840.113556.1.4.803:=524288)`" can be used to find all users or computers marked as trusted for delegation, or unconstrained delegation, which will be covered in a later module on Kerberos Attacks. We can enumerate users with the help of this LDAP filter:

```
Get-ADUser -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select Name,memberof, servicePrincipalName,TrustedForDelegation | fl
```

We can enumerate computers with this setting as well:

- **LDAP Query - Find Trusted Computers**
```
Get-ADComputer -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select DistinguishedName,servicePrincipalName,TrustedForDelegation | fl
```

Lastly, let's search for all users with the "`adminCount`" attribute set to `1` whose "`useraccountcontrol`" attribute is set with the flag "`PASSWD_NOTREQD`," meaning that the account can have a blank password set. To do this, we must combine two LDAP search filters as follows:

```
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)
```

- **LDAP Query - Users With Blank Password**
```
Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl
```

While uncommon, we find accounts without a password set from time to time, so it is always important to enumerate accounts with the `PASSWD_NOTREQD` flag set and check to see if they indeed do not have a password set. This could happen intentionally (perhaps as a timesaver) or accidentally if a user with this flag set changes their password via command line and accidentally presses enter before typing in a password. All organizations should perform periodic account audits and remove this flag from any accounts that have no valid business reason to have it set.

Try out building some filters of your own. This guide Active Directory: LDAP Syntax Filters is a great starting point. https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx

## Recursive Match

We can use the "`RecursiveMatch`" parameter in a similar way that we use the matching rule OID "`1.2.840.113556.1.4.1941`". A good example of this is to find all of the groups that an AD user is a part of, both directly and indirectly. This is also known as "nested group membership." For example, the user `bob.smith` may not be a direct member of the Domain Admins group but has derivative Domain Admin rights because the group Security Operations is a member of the Domain Admins group. We can see this graphically by looking at Active Directory Computers and Users.

We can enumerate this with PowerShell several ways, one way being the "`Get-ADGroupMember`" cmdlet.

- **PowerShell - Members Of Security Operations**
```
Get-ADGroupMember -Identity "Security Operations"
```

As we can see above, the `Security Operations` group is indeed "nested" within the `Domain Admins` group. Therefore any of its members are effectively `Domain Admins`.

Searching for a user's group membership using `Get-ADUser` focusing on the property memberof will not directly show this information.

- **PowerShell - User's Group Membership**
```
Get-ADUser -Identity harry.jones -Properties * | select memberof | ft -Wrap
```

We can find nested group membership with the matching rule OID and the `RecursiveMatch` parameter, as seen in the following examples. The first example shows an AD filter and the `RecursiveMatch` to recursively query for all groups that the user `harry.jones` is a member of.

- **PowerShell - All Groups of User**
```
Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"' | select name
```

Another way to return this same information is by using an LDAPFilter and the matching rule OID.

- **LDAP Query - All Groups of User**
```
Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' |select Name
```

As shown in the above examples, searching recursively in AD can help us enumerate information that standard search queries do not show. Enumerating nested group membership is very important. We may uncover serious misconfigurations within the target AD environment that would otherwise go unnoticed, especially in large organizations with thousands of objects in AD. We will see other ways to enumerate this information and even ways of presenting it in a graphical format, but `RecursiveMatch` is a powerful search parameter that should not be overlooked.

## SearchBase and SearchScope Parameters

Even small Active Directory environments can contain hundreds if not thousands of objects. Active Directory can grow very quickly as users, groups, computers, OUs, etc., are added, and ACLs are set up, which creates an increasingly complex web of relationships. We may also find ourselves in a vast environment, 10-20 years old, with 10s of thousands of objects. Enumerating these environments can become an unwieldy task, so we need to refine our searches.

We can improve the performance of our enumeration commands and scripts and reduce the volume of objects returned by scoping our searches using the "`SearchBase`" parameter. This parameter specifies an Active Directory path to search under and allows us to begin searching for a user account in a specific OU. The "`SearchBase`" parameter accepts an OUs distinguished name (DN) such as "`OU=Employees,DC=INLANEFREIGHT,DC=LOCAL`".

"`SearchScope`" allows us to define how deep into the OU hierarchy we would like to search. This parameter has three levels:

| Name       | Level | Description                                                                                                                                                                                                                       |
|------------|-------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Base`     | `0`   | The object is specified as the SearchBase. For example, if we ask for all users in an OU defining a base scope, we get no results. If we specify a user or use `Get-ADObject`, we get just that user or object returned.            |
| `OneLevel` | `1`   | Searches for objects in the container defined by the SearchBase but not in any sub-containers.                                                                                            |
| `SubTree`  | `2`   | Searches for objects contained by the SearchBase and all child containers, including their children, recursively all the way down the AD hierarchy.                                        |

When querying AD using "`SearchScope`" we can specify the name or the number (i.e., `SearchScope Onelevel` is interpreted the same as "`SearchScope 1`".)

![image](https://github.com/user-attachments/assets/3ee259ad-bb84-4a95-925b-da9f2b1401eb)

In the above example, with the `SearchBase` set to `OU=Employees,DC=INLANEFREIGHT,DC=LOCAL`, a `SearchScope` set to `Base` would attempt to query the OU object (`Employees`) itself. A `SearchScope` set to `OneLevel` would search within the `Employees OU` only. Finally, a `SearchScope` set to `SubTree` would query the `Employees OU` and all of the OUs underneath it, such as `Accounting`, `Contractors`, etc. OUs under those OUs (child containers).

## SearchBase and Search Scope Parameters Examples
Let's look at some examples to illustrate the difference between `Base`, `OneLevel`, and `Subtree`. For these examples, we will focus on the `Employees` OU. In the screenshot of Active Directory Users and Computers below Employees is the `Base`, and specifying it with `Get-ADUser` will return nothing. `OneLevel` will return just the user Amelia Matthews, and `SubTree` will return all users in all child containers under the Employees container.

![image](https://github.com/user-attachments/assets/e4121a83-85af-4846-9ed0-1ef0f21b4fd7)

We can confirm these results using PowerShell. For reference purposes, let's get a count of all AD users under the Employees OU, which shows 970 users.

**PowerShell - Count of All AD Users**

- **PowerShell - Count of All AD Users**
```
(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *).count
```

As expected, specifying a `SearchScope` of Base will return nothing.

- **PowerShell - SearchScope Base**
```
Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Base -Filter *
```

However, if we specify "`Base`" with "`Get-ADObject`" we will get just the object (Employees OU) returned to us.

- **PowerShell - SearchScope Base OU Object**
```
Get-ADObject -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Base -Filter *
```

If we specify `OneLevel` as the `SearchScope`, we get one user returned to us, as expected per the image above.

- **PowerShell - Searchscope OneLevel**
```
Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope OneLevel -Filter *
```

As stated above, the `SearchScope` values are interchangeable, so the same result is returned when specifying 1 as the `SearchScope` value.

- **PowerShell - Searchscope 1**
```
Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope 1 -Filter *
```

Finally, if we specify `Subtree` as the `SearchBase`, we will get all objects within all child containers, which matches the user count we established above.

- **PowerShell - Searchscope Subtree**
```
(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Subtree -Filter *).count
```

# Enumerating Active Directory with Built-in Tools

## User-Account-Control (UAC) Attributes

**User-Account-Control Attributes** control the behavior of domain accounts. These values are not to be confused with the Windows User Account Control technology. Many of these UAC attributes have security relevance:

![image](https://github.com/user-attachments/assets/a5021382-d2cb-4823-a854-603a5e8eebe5)

We can enumerate these values with built-in AD cmdlets:

- **PowerShell - Built-in AD Cmdlets**
```
Get-ADUser -Filter {adminCount -gt 0} -Properties admincount,useraccountcontrol | select Name,useraccountcontrol
```

We still need to convert the `useraccountcontrol` values into their corresponding flags to interpret them. This can be done with this script. Let's take the user `Jenna Smith` with `useraccountcontrol` value `4260384` as an example.

- **PowerShell - UAC Values**
```powershell
################################################################################################
# Convert-UserAccountControlValues.ps1
# 
# AUTHOR: Fabian Müller, Microsoft Deutschland GmbH
# VERSION: 0.1.1
# DATE: 23.11.2012
#
# THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
################################################################################################

Function Set-UserAccountControlValueTable
{
	# see http://support.microsoft.com/kb/305144/en-us
	
    $userAccountControlHashTable = New-Object HashTable
    $userAccountControlHashTable.Add("SCRIPT",1)
    $userAccountControlHashTable.Add("ACCOUNTDISABLE",2)
    $userAccountControlHashTable.Add("HOMEDIR_REQUIRED",8) 
    $userAccountControlHashTable.Add("LOCKOUT",16)
    $userAccountControlHashTable.Add("PASSWD_NOTREQD",32)
    $userAccountControlHashTable.Add("ENCRYPTED_TEXT_PWD_ALLOWED",128)
    $userAccountControlHashTable.Add("TEMP_DUPLICATE_ACCOUNT",256)
    $userAccountControlHashTable.Add("NORMAL_ACCOUNT",512)
    $userAccountControlHashTable.Add("INTERDOMAIN_TRUST_ACCOUNT",2048)
    $userAccountControlHashTable.Add("WORKSTATION_TRUST_ACCOUNT",4096)
    $userAccountControlHashTable.Add("SERVER_TRUST_ACCOUNT",8192)
    $userAccountControlHashTable.Add("DONT_EXPIRE_PASSWORD",65536) 
    $userAccountControlHashTable.Add("MNS_LOGON_ACCOUNT",131072)
    $userAccountControlHashTable.Add("SMARTCARD_REQUIRED",262144)
    $userAccountControlHashTable.Add("TRUSTED_FOR_DELEGATION",524288) 
    $userAccountControlHashTable.Add("NOT_DELEGATED",1048576)
    $userAccountControlHashTable.Add("USE_DES_KEY_ONLY",2097152) 
    $userAccountControlHashTable.Add("DONT_REQ_PREAUTH",4194304) 
    $userAccountControlHashTable.Add("PASSWORD_EXPIRED",8388608) 
    $userAccountControlHashTable.Add("TRUSTED_TO_AUTH_FOR_DELEGATION",16777216) 
    $userAccountControlHashTable.Add("PARTIAL_SECRETS_ACCOUNT",67108864)

    $userAccountControlHashTable = $userAccountControlHashTable.GetEnumerator() | Sort-Object -Property Value 
    return $userAccountControlHashTable
}

Function Get-UserAccountControlFlags($userInput)
{    
        Set-UserAccountControlValueTable | foreach {
	    $binaryAnd = $_.value -band $userInput
	    if ($binaryAnd -ne "0") { write $_ }
    }
}

$userInputUserAccountControl = Read-Host "Please provide the userAccountControl value: "
Get-UserAccountControlFlags($userInputUserAccountControl)
```

```
.\Convert-UserAccountControlValues.ps1
```

We can also use `PowerView` (which will be covered in-depth in subsequent modules) to enumerate these values. We can see that some of the users match the default value of `512` or `Normal_Account` while others would need to be converted. The value for `jenna.smith` does match what our conversion script provided.

- **PowerView - Domain Accounts**
```
Get-DomainUser * -AdminCount | select samaccountname,useraccountcontrol
```

## Enumeration Using Built-In Tools
Tools that sysadmins are themselves likely to use, such as the **PowerShell AD Module**, the **Sysinternals Suite**, and **AD DS Tools**, are likely to be whitelisted and fly under the radar, especially in more mature environments. Several built-in tools can be leveraged for AD enumeration, including:

**DS Tools** is available by default on all modern Windows operating systems but required domain connectivity to perform enumeration activities.

### DS Tools
```
dsquery user "OU=Employees,DC=inlanefreight,DC=local" -name * -scope subtree -limit 0 | dsget user -samid -pwdneverexpires | findstr /V no
```

The **PowerShell Active Directory module** is a group of cmdlets used to manage Active Directory. The installation of the AD PowerShell module requires administrative access.

### AD PowerShell Module
```
Get-ADUser -Filter * -SearchBase 'OU=Admin,DC=inlanefreight,dc=local'
```

**Windows Management Instrumentation (WMI)** can also be used to access and query objects in Active Directory. Many scripting languages can interact with the WMI AD provider, but PowerShell makes this very easy.

### Windows Management Instrumentation (WMI)
```
Get-WmiObject -Class win32_group -Filter "Domain='INLANEFREIGHT'" | Select Caption,Name
```

**Active Directory Service Interfaces (ADSI)** is a set of **COM** interfaces that can query Active Directory. PowerShell again provides an easy way to interact with it.

### AD Service Interfaces (ADSI)
```
([adsisearcher]"(&(objectClass=Computer))").FindAll() | select Path
```
