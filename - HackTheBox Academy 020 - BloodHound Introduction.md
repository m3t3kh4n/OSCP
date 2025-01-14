# BloodHound Overview

## Active Directory Access Management

> @_wald0, @harmj0y, and @CptJesus created BloodHound.

## BloodHound Overview

BloodHound is an open-source tool used by attackers and defenders alike to analyze Active Directory domain security. The tool collects a large amount of data from an Active Directory domain. It uses the graph theory to visually represent the relationship between objects and identify domain attack paths that would have been difficult or impossible to detect with traditional enumeration. As of version 4.0, BloodHound now also supports Azure. Although the primary purpose of this module will be Active Directory, we will introduce AzureHound in the section Azure Enumeration.

Data to be utilized by BloodHound is gathered using the SharpHound collector, which is available in PowerShell and C#. We will discuss data collection in the following sections.

## BloodHound Graph Theory & Cypher Query Language

BloodHound utilizes **Graph Theory**, which are mathematical structures used to model pairwise relations between objects. A graph in this context is made up of **nodes** (_Active Directory objects such as users, groups, computers_, etc.) which is connected by **edges** (_relations between an object such as a member of a group, AdminTo_, etc.). We will discuss nodes and edges further in another section, but let's do an example to see how BloodHound works.

The tool uses **Cypher Query Language** to analyze relationships. Cypher is Neo4j’s graph query language that lets us retrieve data from the graph. It is like SQL for graphs, and was inspired by SQL so it lets us focus on what data we want out of the graph (not how to go get it). It is the easiest graph language to learn by far because of its similarity to other languages and intuitiveness. We will discuss more about Cypher queries later in this module.

Reference: https://en.wikipedia.org/wiki/Graph_theory

Reference: https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html

Reference: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html

Reference: https://neo4j.com/docs/getting-started/current/cypher-intro/

The below diagram shows two nodes, A and B. In this example, we can only go from node A to node B, not the other way.
![image](https://github.com/user-attachments/assets/3b87c2db-2b96-40c1-be60-d5fde7d1371a)

This could simulate A as the user Grace and B as the group SQL Admins, the line between the two is the edge, which in this case is MemberOf. The next graphic show us that in BloodHound, where the user Grace is a member of the SQL Admins group.

![image](https://github.com/user-attachments/assets/05b25173-5492-4cc7-b1cd-7bd9c0b7371f)

Let's see a more complex relationship between nodes. The following graphic shows eight (8) nodes and ten (10) edges. Node H can reach node G, but no node has a direct path to node H. To get to node C from node A, we can hop to node G, move to node F, and then to node C, but that's not the **shortest path**. One of the BloodHound capabilities is to look for the shortest path. In this example, the shortest path from node A to node C is one hop through node B.

![image](https://github.com/user-attachments/assets/c78cb8ea-f2b5-4e57-bb89-42dfeaefb008)

In the previous example, we used BloodHound to find that Grace is a member of SQL Admins, which is pretty simple to discover. We can use the Active Directory Users and Computers GUI or the `net user grace /domain` command. With only this information, we can conclude that Grace doesn't have any path to the Domain Admins group, but that is where BloodHound is much more helpful in helping us identify those relationships between nodes that are not easy to locate.

Let's use BloodHound as our map navigator and ask how to get from the user Grace to the Domain Admins group. Here's the result:

![image](https://github.com/user-attachments/assets/62549235-55a5-40d1-bb72-0adaa00cd77b)

## BloodHound for Enterprise

The SpecterOps team that created BloodHound also created BloodHound Enterprise. An Attack Path Management solution that continuously maps and quantifies Active Directory Attack Paths. Ideal for enterprises that want to constantly monitor the different types of on-premises and cloud attack paths, prioritize their actions, obtain remediation guidance, and continuously measure their security posture.

The good thing about this project is that the BloodHound for Enterprise team uses a common library between the commercial and the FOSS project and introduces **SharpHound Common**: one code base from which both FOSS SharpHound and SharpHound Enterprise are built. This code base enables, among other things:
- Improved documentation.
- Improves the quality and stability of SharpHound for everyone.

> Note: To learn more you can read: Introducing BloodHound 4.1 — The Three Headed Hound.

Reference: https://specterops.io/

Reference: https://bloodhoundenterprise.io/

Reference: https://en.wikipedia.org/wiki/Free_and_open-source_software

Reference: https://github.com/BloodHoundAD/SharpHoundCommon

Reference: https://bloodhoundad.github.io/SharpHoundCommon/index.html

Reference: https://posts.specterops.io/introducing-bloodhound-4-1-the-three-headed-hound-be3c4a808146






