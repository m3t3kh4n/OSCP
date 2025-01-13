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





