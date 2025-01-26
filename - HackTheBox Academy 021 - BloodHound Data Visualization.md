# Visualizing the Data

Command	Description
- Set as Starting Node	Set this node as the starting point in the pathfinding tool. Click this, and we will see this node’s name in the search bar. Then, we can select another node to target after clicking the pathfinding button.
- Set as Ending Node	Set this node as the target node in the pathfinding tool.
- Shortest Paths to Here	This will perform a query to find all shortest paths from any arbitrary node in the database to this node. This may cause a long query time in neo4j and an even longer render time in the BloodHound GUI.
- Shortest Paths to Here from Owned	Find attack paths to this node from any node you have marked as owned.
- Edit Node	This brings up the node editing modal, where you can edit current properties on the node or even add our custom properties to the node.
- Mark Group as Owned	This will internally set the node as owned in the neo4j database, which you can then use in conjunction with other queries such as “Shortest paths to here from Owned”.
- Mark/Unmark Group as High Value	Some nodes are marked as “high value” by default, such as the domain admins group and enterprise admin group. We can use this with other queries, such as “shortest paths to high-value assets”.
- Delete Node	Deletes the node from the neo4j database.


The BloodHound team included a help menu under edges, where we can see information, examples, and references on how to abuse every single edge.

Search Bar
The search bar is one of the elements of BloodHound that we will use the most. We can search for specific objects by their name or type. If we click on a node we searched, its information will be displayed in the node info tab.

If we want to search for a specific type, we can prepend our search with node type, for example, user:peter or group:domain. Let's see this in action:

Active Directory

Group
Domain
Computer
User
OU
GPO
Container
Azure

AZApp
AZRole
AZDevice
AZGroup
AZKeyVault
AZManagementGroup
AZResourceGroup
AZServicePrincipal
AZSubscription
AZTenant
AZUser
AZVM


## Pathfinding

Another great feature in the search bar is Pathfinding. We can use it to find an attack path between two given nodes.

## Upper Right Menu
We will find various options to interact with in the top right corner. Let's explain some of these options:

Refresh: reruns the previous query and shows the results

Export Graph: Saves the current graph in JSON format so it can be imported later. We can also save the current graph as a picture in PNG format.

Import Graph: We can display the JSON formatted graph we exported.

Upload Data: Uploads SharpHound, BloodHound.py, or AzureHound data to Neo4j. We can select the upload data with the upload button or drag and drop the JSON or zip file directly into the BloodHound window.

Note: When we upload, BloodHound will add any new data but ignore any duplicated data.

Note: Zip files cannot be password protected from being uploaded.


Change Layout Type: Changes between hierarchical or force-directed layouts.

Settings: Allows us to adjust the display settings for nodes and edges, enabling query to debug mode, low detail mode, and dark mode.
- Node Collapse Threshold: Collapse nodes at the end of paths that only have one relationship. 0 to Disable, Default 5.
- Edge Label Display: When to display edge labels. If Always Display, edges such as MemberOf, Contains, etc., will always be said.
- Node Label Display: When to display node labels. If Always Display, node names, user names, computer names, etc., will always be displayed.
- Query Debug Mode: Raw queries will appear in Raw Query Box. We will discuss more on this in the Cypher Queries section.
- Low Detail Mode: Graphic adjustments to improve performance.
- Dark Mode: Enable Dark mode for the interface.


About: Shows information about the author and version of the software.

## Shortcuts
- CTRL	Pressing CTRL will cycle through the three different node label display settings - default, always show, always hide.
- Spacebar	Pressing the spacebar will bring up the spotlight window, which lists all currently drawn nodes. Click an item in the list, and the GUI will zoom into and briefly highlight that node.
- Backspace	Pressing backspace will return to the previous graph result rendering. This is the same functionality as clicking the Back button in the search bar.
- S	Pressing the letter s will toggle the expansion or collapse of the information panel below the search bar. This is the same functionality as clicking the More Info button in the search bar.


## Database Info

- Clear Database	Lets users completely clear the database of all nodes, relationships, and properties. This can be useful when starting a new assessment or dealing with outdated data.
- Clear Sessions	Lets users clear all saved sessions from the database.
- Refresh Database Stats	Updates the displayed statistics to reflect any changes made to the database.
- Warming Up Database	Is a process that puts the entire database into memory, which can significantly speed up queries. However, this process can take some time to complete, especially if the database is large.

# Nodes

Nodes are the objects we interact with using BloodHound. These represent Active Directory and Azure objects. However, this section will only focus on Active Directory objects.

When we run SharpHound, it collects specific information from each node based on its type. The nodes that we will find in BloodHound according to version 4.2 are:

- Users	Objects that represent individuals who can log in to a network and access resources. Each user has a unique username and password that allows them to authenticate and access resources such as files, folders, and printers.
- Groups	Used to organize users and computers into logical collections, which can then be used to assign permissions to resources. By assigning permissions to a group, you can easily manage access to resources for multiple users at once.
- Computers	Objects that represent the devices that connect to the network. Each computer object has a unique name and identifier that allows it to be managed and controlled within the domain.
- Domains	A logical grouping of network resources, such as users, groups, and computers. It allows you to manage and control these resources in a centralized manner, providing a single point of administration and security.
- GPOs	Group Policy Objects, are used to define and enforce a set of policies and settings for users and computers within an Active Directory domain. These policies can control a wide range of settings, from user permissions to network configurations.
- OUs	Organizational Units, are containers within a domain that allow you to group and manage resources in a more granular manner. They can contain users, groups, and computers, and can be used to delegate administrative tasks to specific individuals or groups.
- Containers	Containers are similar to OUs, but are used for non-administrative purposes. They can be used to group objects together for organizational purposes, but do not have the same level of administrative control as OUs.

https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/

# Edges

BloodHound uses edges to represent the relationships between objects in the Active Directory (AD) environment. These relationships can include user-to-user, user-to-group, group-to-group, user-to-computer, and many others. Each edge represents a line that connects two objects, with the direction of the line indicating the direction of the relationship.

![image](https://github.com/user-attachments/assets/9fa6f710-814a-4acb-8dfb-25772ce0f777)

List of Edges	
AdminTo	MemberOf	HasSession
ForceChangePassword	AddMembers	AddSelf
CanRDP	CanPSRemote	ExecuteDCOM
SQLAdmin	AllowedToDelegate	DCSync
GetChanges/GetChangesAll	GenericAll	WriteDacl
GenericWrite	WriteOwner	WriteSPN
Owns	AddKeyCredentialLink	ReadLAPSPassword
ReadGMSAPassword	Contains	AllExtendedRights
GPLink	AllowedToAct	AddAllowedToAct
TrustedBy	SyncLAPSPassword	HasSIDHistory
WriteAccountRestrictions		

> **If we don't know how to abuse an edge, we can right-click the edge and see the help provided in BloodHound.**

# Analyzing BloodHound Data

## Mapping out INLANEFREIGHT.HTB

Once the data is imported into BloodHound, we can begin our review from the top down. Let's start with an overall domain analysis by typing domain:INLANEFREIGHT.HTB into the search bar.

From the results of the query, we can see the following information about the INLANEFREIGHT.HTB domain:
- Domain functional level	2016
- Users	34
- Groups	60
- Computers	7
- OUs	6
- GPOs	5

The next step is to look at the **Domain Users** group and see the rights the group has. This is important because every user in the domain will inherit any rights granted to this group, meaning that even a minor misconfiguration could have a major effect on the domain's security.

Domain users have sessions on 2 hosts in the domain, have 31 direct members, and belong to 45 groups due to nested group membership. If we go to the **Local Admin Rights** section we see that it says we have 0, this is because the Domain Users group is not a member of the Administrators group on any of the machines. However, if we move to the **Outbound Object Control** section and click on **Transitive Object Control**" we will find all the objects that as Domain Users we have control over.

Next, we can click on the **pathfinding** button and enter **DOMAIN USERS@INLANEFREIGHT.HTB** in the top field and **DOMAIN ADMINS@INLANEFREIGHT.HTB** in the bottom to see if we have any direct paths to Domain Admin for all users. The query returns no data, which means a path does not exist.

Next, we can start running some of the **Pre-Built Analytics Queries** to find additional interesting information.

It is a good idea to obtain a list of all **Domain Admins**. Here we see 3 direct members of the group and 4 unrolled members due to the peter user being a member of the nested group **ITSecurity**.

Next, look at the **Find Shortest Paths to Domain Admins** query. This returns a few paths. We can see some paths from users who are not members of the "Domain Admins" group. User Gil has AddAllowedToAct privileges on domain controller DC01, user Pedro has GenericAll permissions on container Users, Sarah can gain control of user Pedro and service account svc_backups has control over a GPO that is applied on domain controllers.

![image](https://github.com/user-attachments/assets/955c4c2b-548b-42e6-a3c0-a609cf930bff)

- Find Principals with DCSync Rights	Find accounts that can perform the DCSync attack, which will be covered in a later module.
- Users with Foreign Domain Group Membership	Find users that belong to groups in other domains. This can help mount cross-trust attacks.
- Groups with Foreign Domain Group Membership	Find groups that are part of groups in other domains. This can help mount cross-trust attacks.
- Map Domain Trusts	Find all trust relationships with the current domain.
- Shortest Paths to Unconstrained Delegation Systems	Find the shortest path to hosts with Unconstrained Delegation.
- Shortest Paths from Kerberoastable Users	Show the shortest path to Domain Admins by selecting from all users in a dropdown that can be subjected to a Kerberoasting attack.
- Shortest Path from Owned Principals	If we right-click a node and select Mark user as owned or Mark computer as owned, we can then run this query to see how far we can go from any users/computers that we have marked as "owned". This can be very useful for mounting further attacks.
- Shortest Paths to Domain Admins from Owned Principals	Find the shortest path to Domain Admin access from any user or computer marked as "owned".
- Shortest Paths to High-Value Targets	This will give us the shortest path to any objects that BloodHound already considers a high-value target. It can also be used to find paths to any objects that we right-click on and select Mark X as High Value.


## Finding Sessions
BloodHound indicates the sessions we collect in the Database Info tab. We can also see the active sessions in nodes such as users, groups, or computers.

![image](https://github.com/user-attachments/assets/0eca56bc-b375-44c9-b227-0dffe26aee9a)

In the image above, we can see that we have captured a session from the Domain Admins group. Clicking on the session number will show us the computer to which the user member of the Domain Admins group was connected during the enumeration:

![image](https://github.com/user-attachments/assets/f5ac1679-319a-4c36-b513-ad4d61cf0b24)

## Owned Principals

BloodHound's Mark as Owned feature allows a user to mark a node as owned or controlled, indicating that the node is under their control. This feature is particularly useful for Red Team assessments as it allows them to mark nodes they have compromised or have control over, and quickly identify other nodes in the environment they may be able to target.

To use Mark as Owned, a user can simply right-click on a node in the BloodHound interface and select Mark as Owned. The node will then be marked with a skull icon, indicating that it is owned.

Now we can go to the Analysis tab and select Shortest Path from Owned Principals and we can see what activities to perform with the users, group or teams that we have compromised.

# Cypher Queries

Cypher query to return all users
```
MATCH (u:User) RETURN u
```
This query uses the MATCH keyword to find all nodes labeled as User in the graph. We then use the RETURN keyword to return all the nodes found. Let's examine another query:


Cypher query to return the user peter
```
MATCH (u:User {name:"PETER@INLANEFREIGHT.HTB"}) RETURN u
```
The above query uses the MATCH keyword to find the user with the property name equal to PETER@INLANEFREIGHT.HTB and returns the user.


Cypher query to return the user peter
```
MATCH (u:User) WHERE u.name = "PETER@INLANEFREIGHT.HTB" RETURN u
```

Cypher query to return peter's group membership.
```
MATCH (u:User {name:"PETER@INLANEFREIGHT.HTB"})-[r:MemberOf]->(peterGroups) 
RETURN peterGroups
```

## Cypher Attributes - Definitions

![image](https://github.com/user-attachments/assets/659fe30e-8447-46fb-9997-0e6adb13b7bc)

- **Nodes**	Represented with parentheses around the corresponding attributes and information.
- **Variable**	A placeholder represents a node or a relationship in a query. For example, in the query `MATCH (n:User) RETURN n`, the variable `n` represents the node labeled `User`.
- **Relationships**	Depicted by dashes and arrows, with the relationship type in brackets. These show the direction of the relationship. Ex: `->` shows a relationship going one way, while - depicts a relationship going in both directions. In BloodHound, relationships are usually shown toward other privileges.
- **Label**	Used to group nodes based on their properties or characteristics. Labels are denoted by a colon : and are added to a variable. For example, in the query `MATCH (n:User) RETURN n`, the label `User` is used to group nodes with a user's characteristics.
- **Property**	Used to store additional information about a node or a relationship and is denoted by a curly brace `{}`. For example, in the query `MATCH (n:User {name:"PETER@INLANEFREIGHT.HTB", enabled:TRUE}) RETURN n`, the properties `name` and `enabled` are associated with the node `n` to store additional information about the user.

We can also display the relationship between the User and the Group by returning all variables n,r,g:

- **Cypher query to return the user peter MemberOf relationship**
```
MATCH (n:User {name:"PETER@INLANEFREIGHT.HTB"})-[r:MemberOf]->(g:Group) 
RETURN n,r,g
```
To do this graph in the BloodHound application, we can use the Raw Query bar, but We will need to add another variable, p, and wrap the query inside it, as follow:

- **Cypher query to return the user peter MemberOf relationship**
```
MATCH p=((n:User {name:"PETER@INLANEFREIGHT.HTB"})-[r:MemberOf]->(g:Group)) 
RETURN p
```

## Cypher Keywords
Like SQL, Cypher uses keywords for specifying patterns, filtering, and returning results. The most common keywords are `MATCH`, `WHERE`, and `RETURN`.
- **`MATCH`**	Used before describing the search pattern for finding one or more nodes or relationships.
- **`WHERE`**	Used to add more constraints to specific patterns or filter out unwanted patterns.
- **`RETURN`**	Used to specify the results format and organizes the resulting data. We can return results with specific properties, lists, ordering, etc.

Return Peter's MemberOf relationships
```
MATCH p=((u:User {name:"PETER@INLANEFREIGHT.HTB"})-[r:MemberOf*1..]->(g:Group)) 
RETURN p
```
Here we assign the variables `u` and `g` to User and Group, respectively, and tell BloodHound to find matching nodes using the `MemberOf` relationship (or edge). We are using something new, `1..*`, in this query. In this case, it indicates that the path can have a minimum depth of 1 and a maximum depth of any number. The `*` means that there is no upper limit on the depth of the path. This allows the query to match paths of any depth that start at a node with the label `User` and traverse through relationships of type `MemberOf` to reach a node with the label `Group`.

We can also use a specific number instead of `*` to specify the maximum depth of the path. For example, `MATCH p=(n:User)-[r1:MemberOf*1..2]->(g:Group)` will match paths with a minimum depth of `1` and a maximum depth of `2`, meaning that the user must traverse through precisely one or two "MemberOf" relationships to reach the group node.

Back to the query, the result is assigned to the variable `p` and will return the result of each path that matches the pattern we specified.

Let's play a little bit with this query, and instead of showing both paths, let's match a path where the first group's name contains the substring `ITSECURITY`:

- **Find a path where the first group's name contains ITSECURITY**
```
MATCH p=(n:User)-[r1:MemberOf*1..]->(g:Group)
WHERE nodes(p)[1].name CONTAINS 'ITSECURITY'
RETURN p
```

We have two nodes in the first group, `Domain Users` and `ITSECURITY`. The part `nodes(p)[1].name` refers to the name property of the first node in the path `p` obtained from the variable `nodes(p)`. We use the `CONTAINS` keyword only to return the path where the first group's name contains the substring `ITSECURITY`.

Instead of the `CONTAINS` keyword, we can also use the `=~` operator to check if a string matches a `regular expression`. To match a path where the first group's name contains the substring `ITSECURITY`, we can use the following query:

- **Find a path where the first group's name contains ITSECURITY**
```
MATCH p=(n:User)-[r1:MemberOf*1..]->(g:Group)
WHERE nodes(p)[1].name =~ '(?i)itsecurity.*'
RETURN p
```

We used two elements of a regular expression `(?i)` tells the regular expression engine to ignore the case of the characters in the pattern, and `.*` to match any number of characters.

> Note: We can also use regular expressions in properties or any other element in a cypher query.

Reference: https://neo4j.com/docs/cypher-cheat-sheet/current/


### Analyzing a Basic BloodHound Query

Let's look at a few built-in queries to BloodHound. We can enable the option `Query Debug Mode` in settings, which dumps queries into the `Raw Query` box, allowing us to see the query that BloodHound use behind the scene. The following query calculates the shortest paths to domain admins and is one we will use quite often to catch low-hanging fruit.

- **Shortest paths to domain admins**
```
MATCH p=shortestPath((n)-[*1..]->(m:Group {name:"DOMAIN ADMINS@INLANEFREIGHT.HTB"})) 
WHERE NOT n=m 
RETURN p
```

> Note: The query return by BloodHound includes all relationship (edges) hardcoded which is faster, as it doesn't include Azure Edges. We use the `*..` expression, which means we are looking for any relationship. We did it to make it shorter for the example.

This query comes with a function `shortestPath` is a Cypher function that finds the shortest path between two nodes in a graph. It is used in the MATCH clause of a Cypher query to find the shortest path between a starting node `n` and an ending node `m` that match certain conditions.

We use the `WHERE NOT n=m` condition to exclude the possibility of the starting node and the ending node being the same node, as a node cannot have a path to itself.

## Advanced BloodHound Queries

> **!!! The first query we will show is the most important one. With this query, we can find almost any path in the domain shared by PlainText. He has been using this script to compromise any Active Directory during engagements, labs, and certifications labs.!!!** 

- **ShortestPath from node that contains peter to any node**
```
MATCH p = shortestPath((n)-[*1..]->(c)) 
WHERE n.name =~ '(?i)peter.*' AND NOT c=n 
RETURN p
```

This script search for the shortestPath from any node to any node. In this example, if we manage to compromise Peter, but he doesn't have a path to Domain Admin or a High-Value Target, most likely, we won't get any results using default queries in BloodHound. However, by utilizing this query, we can determine if peter has access to a machine, a user, a group, GPO, or anything in the domain.

The purpose of this script is to streamline the process of exploring our options after successfully compromising a user, computer, or group. If we compromise a user, we employ the query to determine the potential paths we can pursue with that user. Likewise, if we compromise a computer or group, we use the same script to identify the available opportunities for further exploitation.

> Note: We can replace the function `shortestPath` with `allshortestpaths` to get every single relationship available.

If we compromise a user and this script doesn't give you any result, we can use PowerView or SharpView to display user privileges over another object in AD.

- **PowerView Identify ACL**
```
Import-Module c:\tools\PowerView.ps1
Get-DomainObjectAcl -Identity peter -domain INLANEFREIGHT.HTB -ResolveGUIDs
```

> Note: The latest version of BloodHound includes Self privileges, which were not included in previous versions. For more information about using this PowerView method, we can take a look at: ACL Enumeration section in Active Directory Enumeration & Attacks module.


### Custom Queries examples

- **Finds specific rights that the Domain Users group should not have !!!!!!!!!!!!**
```
MATCH p=(g:Group)-[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(c:Computer) 
WHERE g.name STARTS WITH "DOMAIN USERS" 
RETURN p
```

> Some custom queries can only be run against the database from the Neo4j console via the browser accessible at http://localhost:7474/browser with the same credentials when starting BloodHound. For example, we can run this query to find all users with a description field that is not blank. This is an edge case, but it is common for account passwords to be stored in this field.

- **Find all users with a description field that is not blank**
```
MATCH (u:User) 
WHERE u.description IS NOT NULL 
RETURN u.name,u.description
```

- **Find all local administrators and the host they are admin !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!**
```
MATCH (c:Computer) OPTIONAL MATCH (u1:User)-[:AdminTo]->(c) OPTIONAL MATCH (u2:User)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c) WITH COLLECT(u1) + COLLECT(u2) AS TempVar,c UNWIND TempVar AS Admins 
RETURN c.name AS COMPUTER, COUNT(DISTINCT(Admins)) AS ADMIN_COUNT,COLLECT(DISTINCT(Admins.name)) AS USERS 
ORDER BY ADMIN_COUNT DESC
```

- **Find `WriteSPN` edge**
```
MATCH p=((n)-[r:WriteSPN]->(m)) RETURN p
```

Reference: https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12
Reference: https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/

### Saving Custom Queries

On Windows, the `AppData\Roaming\bloodhound` directory holds a variety of configuration files used by BloodHound.

On Linux, these are stored in `/home/<username>/.config/bloodhound` or `/root/.config/bloodhound` if running as root.

BloodHound config directory
```
ls /root/.config/bloodhound
```
The `config.json` file holds the current BloodHound configuration, including performance options, included edges, etc.


The other file that we will focus on is the `customqueries.json` file. By default, it is blank.

We can add to this file as we build and test queries. Clicking on the pencil icon next to Custom Queries in the Queries tab will open this file. As we add custom queries, the list will populate.

BloodHound queries in the Analysis tab are loaded from the PrebuiltQueries.json file. We can find it in the BloodHound directory or Github.

Reference: https://github.com/BloodHoundAD/BloodHound/blob/master/src/components/SearchContainer/Tabs/PrebuiltQueries.json

Reference: https://www.ernw.de/download/BloodHoundWorkshop/ERNW_DogWhispererHandbook.pdf
