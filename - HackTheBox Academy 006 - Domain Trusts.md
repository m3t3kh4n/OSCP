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
































