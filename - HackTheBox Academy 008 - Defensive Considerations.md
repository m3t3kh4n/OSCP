# Defensive Considerations

## Hardening Active Directory

Let's take some time to look at a few hardening measures that can be put in place to stop common TTPs like those we utilized in this module from being successful or providing any helpful information. Our goal as penetration testers is to help provide a better operational picture of our customers' network to their defenders and help improve their security posture. So we should understand some of the common defense tactics that can be implemented and how they would affect the networks we are assessing. These basic hardening steps will do much more for an organization (regardless of size) than purchasing the next big EDR or SIEM tool. Those extra defensive measures and equipment only help if you have a baseline security posture with features like logging enabled and proper documentation and tracking of the hosts within the network.

### Step One: Document and Audit

Proper AD hardening can keep attackers contained and prevent lateral movement, privilege escalation, and access to sensitive data and resources. One of the essential steps in AD hardening is understanding everything present in your AD environment. An audit of everything listed below should be done annually, if not every few months, to ensure your records are up to date. We care about:

#### Things To Document and Track:

- Naming conventions of OUs, computers, users, groups
- DNS, network, and DHCP configurations
- An intimate understanding of all GPOs and the objects that they are applied to
- Assignment of FSMO roles
- Full and current application inventory
- A list of all enterprise hosts and their location
- Any trust relationships we have with other domains or outside entities
- Users who have elevated permissions

#### People, Processes, and Technology

AD hardening can be broken out into the categories People, Process, and Technology. These hardening measures will encompass the hardware, software, and human aspects of any network.

##### People

In even the most hardened environment, users remain the weakest link. Enforcing security best practices for standard users and administrators will prevent "easy wins" for pentesters and malicious attackers. We should also strive to keep our users educated and aware of threats to themselves. The measures below are a great way to start securing the Human element of an AD environment.

- The organization should have a strong password policy, with a password filter that disallows the use of common words (i.e., welcome, password, names of months/days/seasons, and the company name). If possible, an enterprise password manager should be used to assist users with choosing and using complex passwords.
- Rotate passwords periodically for all service accounts.
- Disallow local administrator access on user workstations unless a specific business need exists.
- Disable the default `RID-500 local admin` account and create a new admin account for administration subject to LAPS password rotation.
- Implement split tiers of administration for administrative users. Too often, during an assessment, you will gain access to Domain Administrator credentials on a computer that an administrator uses for all work activities.
- Clean up privileged groups. `Does the organization need 50+ Domain/Enterprise Admins?` Restrict group membership in highly privileged groups to only those users who require this access to perform their day-to-day system administrator duties.
- Where appropriate, place accounts in the `Protected Users` group.
- Disable Kerberos delegation for administrative accounts (the Protected Users group may not do this)

###### Protected Users Group

The Protected Users group first appeared with Window Server 2012 R2. This group can be used to restrict what members of this privileged group can do in a domain. Adding users to Protected Users prevents user credentials from being abused if left in memory on a host.

- **Viewing the Protected Users Group with Get-ADGroup**
```
Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members
```

The group provides the following Domain Controller and device protections:

- Group members can not be delegated with constrained or unconstrained delegation.
- CredSSP will not cache plaintext credentials in memory even if Allow delegating default credentials is set within Group Policy.
- Windows Digest will not cache the user's plaintext password, even if Windows Digest is enabled.
- Members cannot authenticate using NTLM authentication or use DES or RC4 keys.
- After acquiring a TGT, the user's long-term keys or plaintext credentials are not cached.
- Members cannot renew a TGT longer than the original 4-hour TTL.

> Note: The Protected Users group can cause unforeseen issues with authentication, which can easily result in account lockouts. An organization should never place all privileged users in this group without staged testing.

Along with ensuring your users cannot cause harm to themselves, we should consider our policies and procedures for domain access and control.

##### Processes

Maintaining and enforcing policies and procedures that can significantly impact an organization's overall security posture is necessary. Without defined policies, it is impossible to hold an organization's employees accountable, and difficult to respond to an incident without defined and practiced procedures such as a disaster recovery plan. The items below can help to define processes, policies, and procedures.

- Proper policies and procedures for AD asset management.
- - AD host audit, the use of asset tags, and periodic asset inventories can help ensure hosts are not lost.
- Access control policies (user account provisioning/de-provisioning), multi-factor authentication mechanisms.
- Processes for provisioning and decommissioning hosts (i.e., baseline security hardening guideline, gold images)
- AD cleanup policies
- - **Are accounts for former employees removed or just disabled?**
  - **What is the process for removing stale records from AD?**
  - Processes for decommissioning legacy operating systems/services (i.e., proper uninstallation of Exchange when migrating to 0365).
  - Schedule for User, groups, and hosts audit.

##### Technology

Periodically review AD for legacy misconfigurations and new and emerging threats. As changes are made to AD, ensure that common misconfigurations are not introduced. Pay attention to any vulnerabilities introduced by AD and tools or applications utilized in the environment.

- Run tools such as BloodHound, PingCastle, and Grouper periodically to identify AD misconfigurations.
- Ensure that administrators are not storing passwords in the AD account description field.
- Review SYSVOL for scripts containing passwords and other sensitive data.
- Avoid the use of "normal" service accounts, utilizing Group Managed (gMSA) and Managed Service Accounts (MSA) where ever possible to mitigate the risk of Kerberoasting.
- Disable Unconstrained Delegation wherever possible.
- Prevent direct access to Domain Controllers through the use of hardened jump hosts.
- Consider setting the `ms-DS-MachineAccountQuota` attribute to `0`, which disallows users from adding machine accounts and can prevent several attacks such as the noPac attack and Resource-Based Constrained Delegation (RBCD)
- Disable the print spooler service wherever possible to prevent several attacks
- Disable NTLM authentication for Domain Controllers if possible
- Use Extended Protection for Authentication along with enabling Require SSL only to allow HTTPS connections for the Certificate Authority Web Enrollment and Certificate - - - Enrollment Web Service services
- Enable SMB signing and LDAP signing
- Take steps to prevent enumeration with tools like BloodHound
- Ideally, perform quarterly penetration tests/AD security assessments, but if budget constraints exist, these should be performed annually at the very least.
- Test backups for validity and review/practice disaster recovery plans.
- Enable the restriction of anonymous access and prevent null session enumeration by setting the `RestrictNullSessAccess` registry key to `1` to restrict null session access to unauthenticated users.

## Protections By Section

As a different look at this, we have broken out the significant actions by section and correlated controls based on the TTP and a MITRE tag. Each tag corresponds with a section of the Enterprise ATT&CK Matrix found here. Any tag marked as `TA` corresponds to an overarching tactic, while a tag marked as `T###` is a technique found in the matrix under tactics.

Reference: https://attack.mitre.org/tactics/enterprise/

| TTP                     | MITRE Tag    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|-------------------------|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| External Reconnaissance | T1589        | This portion of an attack is extremely hard to detect and defend against. An attacker does not have to interact with your enterprise environment directly, so it's impossible to tell when it is happening. What can be done is to monitor and control the data you release publicly to the world. Job postings, documents (and the metadata left attached), and other open information sources like BGP and DNS records all reveal something about your enterprise. Taking care to scrub documents before release can ensure an attacker cannot glean user naming context from them as an example. The same can be said for not providing detailed information about tools and equipment utilized in your networks via job postings. |
| Internal Reconnaissance | T1595        | For reconnaissance of our internal networks, we have more options. This is often considered an active phase and, as such, will generate network traffic which we can monitor and place defenses based on what we see. Monitoring network traffic for any suspicious bursts of packets of a large volume from any one source or several sources can be indicative of scanning. A properly configured Firewall or Network Intrusion Detection System (NIDS) will spot these trends quickly and alert on the traffic. Depending on the tool or appliance, it may even be able to add a rule blocking traffic from said hosts proactively. The utilization of network monitoring coupled with a SIEM can be crucial to spotting reconnaissance. Properly tuning the Windows Firewall settings or your EDR of choice to not respond to ICMP traffic, among other types of traffic, can help deny an attacker any information they may glean from the results. |
| Poisoning               | T1557        | Utilizing security options like SMB message signing and encrypting traffic with a strong encryption mechanism will go a long way to stopping poisoning & man-in-the-middle attacks. SMB signing utilizes hashed authentication codes and verifies the identity of the sender and recipient of the packet. These actions will break relay attacks since the attacker is just spoofing traffic.                                                                                                                                                                                  |
| Password Spraying       | T1110/003    | This action is perhaps the easiest to defend against and detect. Simple logging and monitoring can tip you off to password spraying attacks in your network. Watching your logs for multiple attempts to login by watching Event IDs 4624 and 4648 for strings of invalid attempts can tip you off to password spraying or brute force attempts to access the host. Having strong password policies, an account lockout policy set, and utilizing two-factor or multi-factor authentication can all help prevent the success of a password spray attack. For a deeper look at the recommended policy settings, check out this article and the NIST documentation. |
| Credentialed Enumeration| TA0006       | There is no real defense you can put in place to stop this method of attack. Once an attacker has valid credentials, they effectively can perform any action that the user is allowed to do. A vigilant defender can detect and put a stop to this, however. Monitoring for unusual activity such as issuing commands from the CLI when a user should not have a need to utilize it. Multiple RDP requests sent from host to host within the network or movement of files from various hosts can all help tip a defender off. If an attacker manages to acquire administrative privileges, this can become much more difficult, but there are network heuristics tools that can be put in place to analyze the network constantly for anomalous activity. Network segmentation can help a lot here. |
| LOTL                    | N/A          | It can be hard to spot an attacker while they are utilizing the resources built-in to host operating systems. This is where having a baseline of network traffic and user behavior comes in handy. If your defenders understand what the day-to-day regular network activity looks like, you have a chance to spot the abnormal. Watching for command shells and utilizing a properly configured Applocker policy can help prevent the use of applications and tools users should not have access to or need.                                                     |
| Kerberoasting           | T1558/003    | Kerberoasting as an attack technique is widely documented, and there are plenty of ways to spot it and defend against it. The number one way to protect against Kerberoasting is to utilize a stronger encryption scheme than RC4 for Kerberos authentication mechanisms. Enforcing strong password policies can help prevent Kerberoasting attacks from being successful. Utilizing Group Managed service accounts is probably the best defense as this makes Kerberoasting no longer possible. Periodically auditing your users' account permissions for excessive group membership can be an effective way to spot issues. |


I wanted to take a second to show everyone how it appears when exploring the ATT&CK framework. We will use the example above of `Kerberoasting` to look at it through the lens of the framework. Kerberoasting is a part of the larger `Tactic tag TA0006 Credential Access` (Green square in the image above). Tactics encompass the overall goal of the actor and will contain various techniques which map to that goal. Within this scope, you will see all manner of credential-stealing techniques. We can scroll down and look for `Steal or Forge Kerberos Tickets`, which is `Technique Tag T1558` (blue square in the image above). This technique contains four sub-techniques (indicated by the .00# beside the technique name) Golden Ticket, Silver Ticket, Kerberoasting, and AS-REP Roasting. Since we care about Kerberoasting, we would select the sub-technique T1558.003 (orange box in the image above), and it will take us to a new page. Here, we can see a general explanation of the technique, the information referencing the ATT&CK platform classification on the top right, examples of its use in the real world, ways to mitigate and detect the tactic, and finally, references for more information at the bottom of the page.

So our technique would be classified under `TA0006/T1558.003`. This is how the Tactic/Technique tree would be read. There are many different ways to navigate the framework. We just wanted to provide some clarification on what we were looking for and how we were defining tactics versus techniques when talking about MITRE ATT&CK in this module. This framework is great to explore if you are curious about a `Tactic` or `Technique` and want more information about it.

These are not an exhaustive list of defensive measures, but they are a strong start. As attackers, if we understand the potential defensive measures we can face during our assessments, we can plan for alternate means of exploitation and movement. We won't win every battle; some defenders may have their environments locked down tight and see every move you make, but others may have missed one of these recommendations. It is important to explore them all, and help provide the defensive team with the best results possible. Also, understanding how the attacks and defenses work will make us improve cybersecurity practitioners overall.

# Additional AD Auditing Techniques

Along with discussing the hardening of an AD domain, we wanted to discuss **AD auditing**. We want to provide our customers with as much information as possible to help solve the potential issues we find. Doing so will give them more data to prove they have a problem and help acquire backing and funding to tackle those fixes. The tools in this section can be utilized to provide different visualizations and data output for this purpose.

## Creating an AD Snapshot with Active Directory Explorer

AD Explorer is part of the Sysinternal Suite and is described as:

"An advanced Active Directory (AD) viewer and editor. You can use AD Explorer to navigate an AD database easily, define favorite locations, view object properties, and attributes without opening dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute."

AD Explorer can also be used to save snapshots of an AD database for offline viewing and comparison. We can take a snapshot of AD at a point in time and explore it later, during the reporting phase, as you would explore any other database. It can also be used to perform a before and after comparison of AD to uncover changes in objects, attributes, and security permissions.

When we first load the tool, we are prompted for login credentials or to load a previous snapshot. We can log in with any valid domain user.

### Logging in with AD Explorer

![image](https://github.com/user-attachments/assets/b47a6506-d249-4127-9867-36da6bebf2af)

Once logged in, we can freely browse AD and view information about all objects.

### Browsing AD with AD Explorer

![image](https://github.com/user-attachments/assets/bc0fc093-1f71-4f30-a6b4-c4f3b2e0993b)

To take a snapshot of AD, go to File --> Create Snapshot and enter a name for the snapshot. Once it is complete, we can move it offline for further analysis.

### Creating a Snapshot of AD with AD Explorer

![image](https://github.com/user-attachments/assets/c86ad1d1-8403-4a3c-aea9-4a4bcd8201b5)

## PingCastle

PingCastle is a powerful tool that evaluates the security posture of an AD environment and provides us the results in several different maps and graphs. Thinking about security for a second, if you do not have an active inventory of the hosts in your enterprise, PingCastle can be a great resource to help you gather one in a nice user-readable map of the domain. PingCastle is different from tools such as PowerView and BloodHound because, aside from providing us with enumeration data that can inform our attacks, it also provides a detailed report of the target domain's security level using a methodology based on a risk assessment/maturity framework. The scoring shown in the report is based on the Capability Maturity Model Integration (CMMI). For a quick look at the help context provided, you can issue the --help switch in cmd-prompt.

> Note: If you are having issues with starting the tool, please change the date of the system to a date before 31st of July 2023 using the Control Panel (Set the time and date).

- **Viewing the PingCastle Help Menu**
```
PingCastle.exe --help
```

### Running PingCastle

To run PingCastle, we can call the executable by typing `PingCastle.exe` into our CMD or PowerShell window or by clicking on the executable, and it will drop us into interactive mode, presenting us with a menu of options inside the Terminal User Interface (TUI).

The default option is the `healthcheck` run, which will establish a baseline overview of the domain, and provide us with pertinent information dealing with misconfigurations and vulnerabilities. Even better, PingCastle can report recent vulnerability susceptibility, our shares, trusts, the delegation of permissions, and much more about our user and computer states. Under the Scanner option, we can find most of these checks.

### Viewing The Report

Throughout the report, there are sections such as domain, user, group, and trust information and a specific table calling out "anomalies" or issues that may require immediate attention. We will also be presented with the domain's overall risk score.

Aside from being helpful in performing very thorough domain enumeration when combined with other tools, PingCastle can be helpful to give clients a quick analysis of their domain security posture, or can be used by internal teams to self-assess and find areas of concern or opportunities for further hardening. Take some time to explore the reports and maps PingCastle can generate on the Inlanefreight domain.

## Group Policy

With group policy being a large portion of how AD user and computer management is done, it's only logical that we would want to audit their settings and highlight any potential holes. Group3r is an excellent tool for this.

### Group3r

`Group3r` is a tool purpose-built to find vulnerabilities in Active Directory associated Group Policy. Group3r must be run from a domain-joined host with a domain user (it does not need to be an administrator), or in the context of a domain user (i.e., using `runas /netonly`).

Reference: https://github.com/Group3r/Group3r

- **Group3r Basic Usage**
```
group3r.exe -f <filepath-name.log>
```

When running Group3r, we must specify the `-s` or the `-f` flag. These will specify whether to send results to `stdout` (`-s`), or to the file we want to send the results to (`-f`). For more options and usage information, utilize the `-h` flag, or check out the usage info at the link above.

When reading the output from Group3r, each indentation is a different level, so no indent will be the GPO, one indent will be policy settings, and another will be findings in those settings. Below we will take a look at the output shown from a finding.

## ADRecon

Finally, there are several other tools out there that are useful for gathering a large amount of data from AD at once. In an assessment where stealth is not required, it is also worth running a tool like **ADRecon** and analyzing the results, just in case all of our enumeration missed something minor that may be useful to us or worth pointing out to our client.

Reference: https://github.com/adrecon/ADRecon

- **Running ADRecon**
```
.\ADRecon.ps1
```

Once done, ADRecon will drop a report for us in a new folder under the directory we executed from. We can see an example of the results in the terminal below. You will get a report in HTML format and a folder with CSV results. When generating the report, it should be noted that the program Excel needs to be installed, or the script will not automatically generate the report in that manner; it will just leave you with the .csv files. If you want output for Group Policy, you need to ensure the host you run from has the `GroupPolicy` PowerShell module installed. We can go back later and generate the Excel report from another host using the `-GenExcel` switch and feeding in the report folder.
