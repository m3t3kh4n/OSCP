# Access Control List (ACL) Abuse Primer
For security reasons, not all users and computers in an AD environment can access all objects and files. These types of permissions are controlled through Access Control Lists (ACLs).

## Access Control List (ACL) Overview
ACLs are lists that define a) who has access to which asset/resource and b) the level of access they are provisioned. The settings themselves in an ACL are called **Access Control Entries (ACEs).** Each ACE maps back to a user, group, or process (also known as security principals) and defines the rights granted to that principal. Every object has an ACL, but can have multiple ACEs because multiple security principals can access objects in AD.

There are two types of ACLs:

1. **Discretionary Access Control List (DACL)** - defines which security principals are granted or denied access to an object. DACLs are made up of ACEs that either allow or deny access. When someone attempts to access an object, the system will check the DACL for the level of access that is permitted. **If a DACL does not exist for an object, all who attempt to access the object are granted full rights**. **If a DACL exists, but does not have any ACE entries specifying specific security settings, the system will deny access to all users, groups, or processes attempting to access it**.
2. **System Access Control Lists (SACL)** - allow administrators to log access attempts made to secured objects.

We see the ACL for the user account forend in the image below. Each item under Permission entries makes up the DACL for the user account, while the individual entries (such as Full Control or Change Password) are ACE entries showing rights granted over this user object to various users and groups.

![image](https://github.com/user-attachments/assets/d413d307-f9e2-42c0-8dc7-5ec400b240bd)

> The SACLs can be seen within the Auditing tab.

## Access Control Entries (ACEs)
There are three main types of ACEs that can be applied to all securable objects in AD:

1. **Access denied ACE**:	Used within a DACL to show that a user or group is explicitly denied access to an object
2. **Access allowed ACE**:	Used within a DACL to show that a user or group is explicitly granted access to an object
3. **System audit ACE**:	Used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred

Each ACE is made up of the following four components:

1. The security identifier (SID) of the user/group that has access to the object (or principal name graphically)
2. A flag denoting the type of ACE (access denied, allowed, or system audit ACE)
3. A set of flags that specify whether or not child containers/objects can inherit the given ACE entry from the primary or parent object
4. An access mask which is a 32-bit value that defines the rights granted to an object

Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN

We can view this graphically in _Active Directory Users and Computers (ADUC)_. In the example image below, we can see the following for the ACE entry for the user forend:

![image](https://github.com/user-attachments/assets/a5ea59c0-c4ca-473c-9969-61cad8c2c6d2)

1. The security principal is Angela Dunn (adunn@inlanefreight.local)
2. The ACE type is Allow
3. Inheritance applies to the "This object and all descendant objects,” meaning any child objects of the forend object would have the same permissions granted
4. The rights granted to the object, again shown graphically in this example

> When access control lists are checked to determine permissions, they are checked from top to bottom until an access denied is found in the list.

## Why are ACEs Important?
```
ForceChangePassword abused with Set-DomainUserPassword
Add Members abused with Add-DomainGroupMember
GenericAll abused with Set-DomainUserPassword or Add-DomainGroupMember
GenericWrite abused with Set-DomainObject
WriteOwner abused with Set-DomainObjectOwner
WriteDACL abused with Add-DomainObjectACL
AllExtendedRights abused with Set-DomainUserPassword or Add-DomainGroupMember
Addself abused with Add-DomainGroupMember
```

we will cover enumerating and leveraging four specific ACEs to highlight the power of ACL attacks:
- **`ForceChangePassword`** - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
- **`GenericWrite`** - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
- **`AddSelf`** - shows security groups that a user can add themselves to.
- **`GenericAll`** - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the Local Administrator Password Solution (LAPS) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

***!!! MAIN REFERENCE: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html !!!***

***Reference: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword***

***Reference: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericwrite***

***Reference: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall***

![image](https://github.com/user-attachments/assets/76139319-c00f-4651-bb29-037b22a9525d)

This graphic, adapted from a graphic created by Charlie Bromberg (Shutdown), shows an excellent breakdown of the varying possible ACE attacks and the tools to perform these attacks from both Windows and Linux (if applicable). In the following few sections, we will mainly cover enumerating and performing these attacks from a Windows attack host with mentions of how these attacks could be performed from Linux. A later module specifically on ACL Attacks will go much further in-depth on each of the attacks listed in this graphic and how to perform them from Windows and Linux.

We will run into many other interesting ACEs (privileges) in Active Directory from time to time. The methodology for enumerating possible ACL attacks using tools such as BloodHound and PowerView and even built-in AD management tools should be adaptable enough to assist us whenever we encounter new privileges in the wild that we may not yet be familiar with. For example, we may import data into BloodHound and see that a user we have control over (or can potentially take over) has the rights to read the password for a Group Managed Service Account (gMSA) through the ReadGMSAPassword edge. In this case, there are tools such as GMSAPasswordReader that we could use, along with other methods, to obtain the password for the service account in question. Other times we may come across extended rights such as Unexpire-Password or Reanimate-Tombstones using PowerView and have to do a bit of research to figure out how to exploit these for our benefit. It's worth familiarizing yourself with all of the BloodHound edges and as many Active Directory Extended Rights as possible as you never know when you may encounter a less common one during an assessment.

Reference: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#readgmsapassword

Reference: https://github.com/rvazarkar/GMSAPasswordReader

Reference: https://learn.microsoft.com/en-us/windows/win32/adschema/r-unexpire-password

Reference: https://learn.microsoft.com/en-us/windows/win32/adschema/r-reanimate-tombstones

Reference: https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights

## ACL Attacks in the Wild

- Abusing forgot password permissions:	Help Desk and other IT users are often granted permissions to perform password resets and other privileged tasks. If we can take over an account with these privileges (or an account in a group that confers these privileges on its users), we may be able to perform a password reset for a more privileged account in the domain.
- Abusing group membership management:	It's also common to see Help Desk and other staff that have the right to add/remove users from a given group. It is always worth enumerating this further, as sometimes we may be able to add an account that we control into a privileged built-in AD group or a group that grants us some sort of interesting privilege.
- Excessive user rights:	We also commonly see user, computer, and group objects with excessive rights that a client is likely unaware of. This could occur after some sort of software install (Exchange, for example, adds many ACL changes into the environment at install time) or some kind of legacy or accidental configuration that gives a user unintended rights. Sometimes we may take over an account that was given certain rights out of convenience or to solve a nagging problem more quickly.

# ACL Enumeration

## Enumerating ACLs with PowerView
- Using Find-InterestingDomainAcl
```
Find-InterestingDomainAcl
```
- Using Get-DomainObjectACL. we are using this function to find all domain objects that our user has rights over by mapping the user's SID using the $sid variable to the SecurityIdentifier property which is what tells us who has the given right over an object. One important thing to note is that if we search without the flag `ResolveGUIDs`, we will see results like the below, where the right `ExtendedRight` does not give us a clear picture of what ACE entry the user wley has over damundsen. This is because the `ObjectAceType` property is returning a GUID value that is not human readable.
```
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

> We could Google for the GUID value 00299570-246d-11d0-a768-00aa006e0529 and uncover this page showing that the user has the right to force change the other user's password.

Reference: https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password

- **Performing a Reverse Search & Mapping to a GUID Value**
```
$guid= "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```

> This gave us our answer, but would be highly inefficient during an assessment. PowerView has the **`ResolveGUIDs`** flag, which does this very thing for us. Notice how the output changes when we include this flag to show the human-readable format of the ObjectAceType property as User-Force-Change-Password.

- **Using the -ResolveGUIDs Flag**
```
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} -Verbose
```

```
Get-DomainObjectACL -ResolveGUIDs -Identity "GPO Management" |
  Where-Object { $_.SecurityIdentifier -eq $sid } |
  Select-Object -First 1 |
  Select-Object ObjectAceType
```

Some manual work if no tools available:

- we've first made a list of all domain users with the following command
```
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```
- We then read each line of the file using a foreach loop, and use the `Get-Acl` cmdlet to retrieve ACL information for each domain user by feeding each line of the ad_users.txt file to the `Get-ADUser` cmdlet. We then select just the `Access property`, which will give us information about access rights. Finally, we set the `IdentityReference` property to the user we are in control of (or looking to see what rights they have), in our case, wley.
```
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```
Once we have this data, we could follow the same methods shown above to convert the GUID to a human-readable format to understand what rights we have over the target user.

- Investigating the Help Desk Level 1 Group with Get-DomainGroup
```
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```

> user has `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-In-Filtered-Set` rights over the domain object. This means that this user can be leveraged to perform a DCSync attack. We will cover this attack in-depth in the DCSync section.

## Enumerating ACLs with BloodHound
we can set the wley user as our **starting node**, select the `Node Info` tab and scroll down to `Outbound Control Rights`. This option will show us objects we have control over directly, via group membership, and the number of objects that our user could lead to us controlling via ACL attack paths under Transitive Object Control. If we click on the 1 next to `First Degree Object Control`, we see the first set of rights that we enumerated, `ForceChangePassword` over the damundsen user.

![image](https://github.com/user-attachments/assets/555a7023-3333-41fd-acf3-a8ee61447867)

If we right-click on the line between the two objects, a menu will pop up. If we select Help, we will be presented with help around abusing this ACE, including:
- More info on the specific right, tools, and commands that can be used to pull off this attack
- Operational Security (Opsec) considerations
- External references.











