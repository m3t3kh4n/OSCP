# Mapping and Enumeration with SMB

| Command                                                    | Description                                                                                      |
|------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `crackmapexec smb <target> -u <u> -p <p> --loggedon-users` | Enumerate logged users on the target                                                            |
| `crackmapexec smb <target> -u <u> -p <p> --sessions`       | Enumerate active sessions on the target                                                         |
| `crackmapexec smb <target> -u <u> -p <p> --disks`          | Enumerate disks on the target                                                                   |
| `crackmapexec smb <target> -u <u> -p <p> --computers`      | Enumerate computers on the target domain                                                        |
| `crackmapexec smb <target> -u <u> -p <p> --wmi`            | Issues the specified WMI query                                                                  |
| `crackmapexec smb <target> -u <u> -p <p> --wmi-namespace`  | WMI Namespace (default: `root\cimv2`)                                                           |
| `crackmapexec smb <target> -u <u> -p <p> --rid-brute`      | Enumerate users by bruteforcing the RID on the target                                           |
| `crackmapexec smb <target> -u <u> -p <p> --local-groups`   | Enumerate local groups, and if a group is specified, its members are enumerated                 |
| `crackmapexec smb <target> -u <u> -p <p> --shares`         | Enumerate permissions on all shares of the target                                               |
| `crackmapexec smb <target> -u <u> -p <p> --users`          | Enumerate domain users on the target                                                            |
| `crackmapexec smb <target> -u <u> -p <p> --groups`         | Enumerate domain groups on the target                                                           |
| `crackmapexec smb <target> -u <u> -p <p> --groups <groupname>`| Enumerate groups members on the target                                                           |
| `crackmapexec smb <target> -u <u> -p <p> --pass-pol`       | Retrieve the password policy of the domain                                                      |

1. Enumerate active sessions / logged users on the target

If we are looking for a particular user, we can use the option --loggedon-users-filter followed by the name of the user we are looking for. In case we are looking for multiple users, it also supports regex.
```
crackmapexec smb 10.129.203.121 -u robert -p Inlanefreight01! --loggedon-users --loggedon-users-filter julio
```

## Enumerate LAPS

The **Local Administrator Password Solution (LAPS)** provides management of local account passwords of domain-joined computers. Passwords are stored in Active Directory (AD) and protected by ACL, so only eligible users can read them or request a reset. If LAPS is used inside the domain and we compromise an account that can read LAPS passwords, we can use the option `--laps` with a list of targets and execute commands or use other options such as `--sam`.

```
cme ldap domain.local -u <> -p <> -M laps
```
```
cme smb domain.local -u <> -p <> --laps
```
```
cme smb domain.local -u <> -p <> --laps --sam 
```

Reference: https://wiki.porchetta.industries/smb-protocol/defeating-laps

> Note: If the default administrator account name is not "administrator," add the username after the option `--laps username`.

> By default, --rid-brute enumerate objects brute forcing RIDs up to 4000. We can modify its behavior using `--rid-brute [MAX_RID]`.

> The `--rid-brute` option can be used to retrieve user names and other Active Directory objects that match the brute-forced IDs. It can also be used to enumerate domain accounts if `NULL Authentication` is enabled. It's important to remember that this option can be used in these ways.

> Note: At the time of writing `--local-group` only works against a Domain Controller, and querying a group using the group name doesn't work.


- **Using WMI to Query if Sysmon is Running**
```
crackmapexec smb 10.129.203.121 -u robert -p Inlanefreight01! --wmi "SELECT Caption,ProcessId FROM Win32_Process WHERE Caption LIKE '%sysmon%'"
```
WMI organizes its classes in a hierarchical namespace. To perform a query, we must know the Class Name and the Namespace in which it is located. In the above example, query the class `Win32_Process` in the namespace `root\cimv2`. We didn't specify the namespace because, by default, CME use `root\cimv2` (we can see that information in the --help menu).

To query another namespace, we need to specify it. Let's, for example, query `MSPower_DeviceEnable` class, which is within the namespace `root\WMI`. This class holds information about devices that should dynamically power on and off while the system works. To learn more about how to find WMI classes that are related to a specific topic, we can use Microsoft and 3rd party documentation from wutils.com.

Reference: https://wutils.com/wmi/

- **Quering root\WMI Namespace**
```
crackmapexec smb 10.129.203.121 -u robert -p Inlanefreight01! --wmi "SELECT * FROM MSPower_DeviceEnable" --wmi-namespace "root\WMI"
```

> Note: Commonly, to query WMI, we will need to have administrative privileges, but an administrator can configure a non-administrator account to query WMI. If that's the case, we can use a non-administrator account to perform WMI queries.

# LDAP and RDP Enumeration










