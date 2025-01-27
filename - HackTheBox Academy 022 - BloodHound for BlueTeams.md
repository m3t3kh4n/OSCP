# BloodHound for BlueTeams

- **BlueHound**
- **PlumHound**

Reference: https://github.com/zeronetworks/BlueHound

## BlueHound
BlueHound is an open-source tool that helps blue teams identify critical security issues by combining information about user permissions, network access, and unpatched vulnerabilities. BlueHound reveals the paths attackers would take if they were inside network.

BlueHound main features include:

- Full Automation: We can perform the entire cycle of collection, analysis, and reporting with just a click of a button.
- Community Driven: The tool facilitates sharing, making it easy to share knowledge, best practices, collection methodologies, and more by exporting and importing BlueHound configuration.
- Easy Reporting: We can create a customized report intuitively without the need to write any code.
- Easy Customization: Users can add any custom collection method to BlueHound, and even include their custom parameters or icons for their graphs.

The Data Import option in BlueHound allows us to automatically import data from sources such as **SharpHound**, **ShotHound**, **Vulnerability Scanners**, etc. We will disable all options but SharpHound.

We can also automate SharpHound collection using the `schedule` option and select its frequency (daily, weekly, or monthly):

Next, we can use the `Query Runner` option in the menu and click `RUN ALL` to prepare the reports.

### BlueHound Customization

BlueHound allows us to modify existing queries, add new queries, create new tabs, and visualize the data according to our needs.

To create a new query, we can click on the box with the `+` sign, define a report name, click on the three vertical dots, define the type and size, and include our query. In the following example, we will create a table that consists of the number of enabled users of the active directory with the following query:

Let's import the custom dashboard C:\Tools\bluehound_dashboard_htb.json with the following steps:
1. Go to Import Config.
2. Select the file to import and import it.
3. Go to the Configurations tab and complete the information (Domain Controllers, Domain Admins, and SRV for this example).
4. Close BlueHound (some times BlueHound freeze while trying to run some queries. If it happens, we can close and re-open it).
5. Open BlueHound and click on Query Runner.
6. Click on RUN ALL to fill all reports with data.

Reference: https://youtu.be/WVup5tnURoM

Reference: https://zeronetworks.com/blog/bluehound-community-driven-resilience/

Reference: https://www.youtube.com/watch?app=desktop&v=76MWt8uugAg


## PlumHound

PlumHound operates by wrapping BloodHoundAD's powerhouse graphical Neo4J backend cypher queries into operations-consumable reports. Analyzing the output of PlumHound can steer security teams in identifying and hardening common Active Directory configuration vulnerabilities and oversights.

Reference; https://github.com/PlumHound/PlumHound

PlumHound operates by wrapping BloodHoundAD's powerhouse graphical Neo4J backend cypher queries into operations-consumable reports. Analyzing the output of PlumHound can steer security teams in identifying and hardening common Active Directory configuration vulnerabilities and oversights.


### Using PlumHound Path Analyzer

PlumHound has multiple uses and different things we can do with this tool. In this example, we will use the **Path Analyzer** option (`-ap`) to understand what relationship we have to remove to break the attack paths we detect.

The Analyze Path function requires a `label`, or a `start node` and an `end node`, and then iterates through all paths to identify which relationship(s) to remove to break the attack path. This is useful when you want to provide your AD Admins with concrete actions they can take to improve your overall AD Security Posture.

Let's take as an example the dangerous `Domain Users` permissions between Domain Users and `WS01`, and identify which privilege we need to remove to break the path:



## Other Tools

Reference; https://github.com/improsec/ImproHound

Reference: https://github.com/idnahacks/GoodHound

ImproHound helps identify AD attack paths by breaking down the AD tier model, while GoodHound helps prioritize remediation efforts by determining the busiest paths to high-value targets.
