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

# BloodHound Setup and Installation

BloodHound use Neo4j, a graph database management system designed to store, manage, and query data represented in a graph. It is a NoSQL database that uses a graph data model to represent and store data, with nodes and edges representing the data and relationships, respectively. This allows Neo4j to represent complex and interconnected data structures more intuitively and efficiently than traditional relational databases.

Neo4j is written in Java and requires a Java Virtual Machine (JVM) to run.

BloodHound can be installed on Windows, Linux, and macOS. We will need to install Java and Neo4j and then download the BloodHound GUI. We can also build the BloodHound GUI from the source, but we won't cover that step in this section. If you want to build from the source, you can read BloodHound official documentation.

We will do the installation in 3 steps:
1. Install Java.
2. Install Neo4j.
3. Install BloodHound.

Reference: https://neo4j.com/

Reference: https://bloodhound.readthedocs.io/en/latest/index.html

> Note: BloodHound 4.2 is installed in PwnBox and ready to use. Both binaries are in the path, you can use `sudo neo4j console` to start the Neo4j database and `bloodhound` to launch BloodHound GUI. BloodHound is installed on the target machine. It is not necessary to install it. To run it we would only need to start the database with the following command `net start neo4j` and execute `bloodhound.exe` which is in the `C:\Tools` folder.

## Windows Installation

We first need to download and install Java Oracle JDK 11. We need to register an account before downloading Java from their website. Once we download the installation file, we can silently install it using the following command:

Reference: https://www.oracle.com/java/technologies/javase-jdk11-downloads.html

- **Install Java Silently**
```
.\jdk-11.0.17_windows-x64_bin.exe /s
```

Next, we need to install Neo4j. We can get the complete list of available versions in the Neo4j Download Center. We will use Neo4j 4.4, the latest version at the time of writing is Neo4j 4.4.16. Once downloaded, _open Powershell, running as administrator, and extract the content of the file_:

Reference: https://neo4j.com/download-center/#community

Reference: https://go.neo4j.com/download-thanks.html?edition=community&release=4.4.16&flavour=winzip

- **Unzip Neo4j**
```
Expand-Archive .\neo4j-community-4.4.16-windows.zip .
```

> Note: Neo4j 5, the latest version, suffers from severe performance regression issues, _this is why we are not using version 5_. For more information visit: BloodHound Official Documentation.

Reference: https://bloodhound.readthedocs.io/en/latest/installation/windows.html

Next, we need to install Neo4j. To install it as a service, we need to move to the `.\neo4j-community-*\bin\` directory and execute the following command `neo4j.bat install-service`:

- **Install Neo4j Service**
```
.\neo4j-community-4.4.16\bin\neo4j.bat install-service
```

> Note: At this point, we may see an error about Java not being found or the wrong version of Java running. Ensure your `JAVA_HOME` environment variable is set to the JDK folder (example: `C:\Program Files\Java\jdk-11.0.17`); this is done automatically after installation. Still, if the installation fails, we must ensure everything is configured correctly.

Once the service is installed, we can start the service:

- **Start Service**
```
net start neo4j
```

### Configure Neo4j Database

To configure the Neo4j database, open a web browser and navigate to the Neo4j web console at `http://localhost:7474/`:

![image](https://github.com/user-attachments/assets/fb3410ca-5777-4fe0-95a2-87c8a0806226)

Authenticate to Neo4j in the web console with username `neo4j` and password `neo4j`, leave the database empty, and once prompted, change the password.

![image](https://github.com/user-attachments/assets/10664c12-3feb-4a4c-8cad-ada18b66b8eb)

### Download BloodHound GUI

1. Download the latest version of the BloodHound GUI for Windows from https://github.com/BloodHoundAD/BloodHound/releases.

![image](https://github.com/user-attachments/assets/b2908844-e668-470f-a5c1-ce166db82221)

> Note: We may get a warning from the Browser or the AV that the file is malicious. Ignore and allow the download.

2. Unzip the folder and double-click BloodHound.exe.
3. Authenticate with the credentials you set up for neo4j.

![image](https://github.com/user-attachments/assets/0bf58a76-c5cd-4218-9ddc-86ab34570a51)

## Linux Installation

The first thing we need to do is download and install Java Oracle JDK 11. We will update our apt sources to install the correct package:

- **Updating APT sources to install Java**
```
echo "deb http://httpredir.debian.org/debian stretch-backports main" | sudo tee -a /etc/apt/sources.list.d/stretch-backports.list
sudo apt-get update
```

With this update, if Java is not installed when we try to install Neo4j, it will automatically install it as part of the Neo4j installation. Let's add the apt sources for Neo4j installation:

- **Updating APT sources to install Neo4j**
```
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
```
Before installing Neo4j, we need to install the `apt-transport-https` package with apt:

- **Installing required packages**
```
sudo apt-get install apt-transport-https
```

Now we can install Neo4j. Let's first list the available options and pick the latest 4.4.X version.

- **Installing Neo4j**
```
sudo apt list -a neo4j
```

At the time of writing. The latest version is Neo4j 4.4.16, let's install that version with the following command:

- **Installing Neo4j 4.4.X**
```
sudo apt install neo4j=1:4.4.16 -y
```

Next, we need to make sure we are using Java 11. We can update which java version our operating system will use with the following command:

- **Change Java version to 11**
```
sudo update-alternatives --config java
```

> Note: Option 1 correspond to Java 11. The option may be different in your system.

We can start Neo4j as a console application to verify it starts up without errors:

- **Running Neo4j as console**
```
cd /usr/bin
sudo ./neo4j console
```

To start and stop the service, we can use the following commands:

- **Start Neo4j**
```
sudo systemctl start neo4j
```

- **Stop Neo4j**
```
sudo systemctl stop neo4j
```

> Note: It is very common for people to host Neo4j on a Linux system but use the BloodHound GUI on a different system. Neo4j, by default, only allows local connections. To allow remote connections, open the neo4j configuration file located at `/etc/neo4j/neo4j.conf` and edit this line:
```
#dbms.default_listen_address=0.0.0.0
```
Remove the `#` character to uncomment the line. _Save the file, then start neo4j up again_.

### Configure Neo4j Database
To configure the Neo4j database, we will do the same steps we did on Windows:

Open a web browser and navigate to the Neo4j web console at http://localhost:7474/:
![image](https://github.com/user-attachments/assets/aa891d8e-0306-451d-998d-4ff5be7467ec)

Change Neo4j default credentials. Authenticate to neo4j in the web console with username neo4j and password neo4j, leave the database empty, and once prompted, change the password.

![image](https://github.com/user-attachments/assets/d40842b8-0b70-40f3-9706-e9a4a1ccf542)


### Download BloodHound GUI

1. Download the latest version of the BloodHound GUI for Linux from https://github.com/BloodHoundAD/BloodHound/releases.
![image](https://github.com/user-attachments/assets/a3868210-3141-4c7c-a9fe-eda17e500568)

2. Unzip the folder, then run BloodHound with the `--no-sandbox` flag:

- **Unzip BloodHound**
```
unzip BloodHound-linux-x64.zip
```

- **Execute BloodHound**
```
cd BloodHound-linux-x64/
./BloodHound --no-sandbox
```

3. Authenticate with the credentials you set up for neo4j.
![image](https://github.com/user-attachments/assets/b5615144-be57-4643-90f6-4a1e49b424a3)

## MacOS Install
To install BloodHound in MacOS, we can follow the steps provided in BloodHound official documentation.

## Updating BloodHound requirements (Linux)
In case we have already installed BloodHound, and we need to update it to support the latest version, we can update Neo4j and Java with the following commands:

- **Update Neo4j**
```
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
```

- **Install Neo4j 4.4.X**
```
sudo apt install neo4j=1:4.4.16 -y
```

> Note: Make sure to change the Java version to 11 as mention in the installation steps.

## Recovering Neo4j Credentials
In case we can't access the Neo4j database with the default credentials, we can follow the next steps to reset the default credentials:

1. Stop neo4j if it is running
```
sudo systemctl stop neo4j
```
2. edit `/etc/neo4j/neo4j.conf`, and uncomment `dbms.security.auth_enabled=false`.
3. Start neo4j console:
```
sudo neo4j console
```
4. Navigate to `http://localhost:7474/` and click `Connect` to log in without credentials.
5. Set a new password for the neo4j account with the following query: `ALTER USER neo4j SET PASSWORD 'Password123';`
![image](https://github.com/user-attachments/assets/332260fe-960d-4bc0-afed-9464b007289e)

6. Stop neo4j service.
7. Edit `/etc/neo4j/neo4j.conf`, and comment out the `dbms.security.auth_enabled=false`.
8. Start Neo4j and use the new password.
