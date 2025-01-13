# LDAP Anonymous Bind

## Leveraging LDAP Anonymous Bind

LDAP anonymous binds allow unauthenticated attackers to retrieve information from the domain, such as a full listing of users, groups, computers, user account attributes, and the domain password policy. Linux hosts running open-source versions of LDAP and Linux vCenter appliances are often configured to allow anonymous binds.

When an LDAP server allows anonymous base binds, an attacker does not need to know a base object to query a considerable amount of information from the domain. This can also be leveraged to mount a password spraying attack or read information such as passwords stored in account description fields. Tools such as **`windapsearch`** and **`ldapsearch`** can be utilized to enumerate domain information via an anonymous LDAP bind. Information that we obtain from an anonymous LDAP bind can be leveraged to mount a password spraying or AS-REPRoasting attack, read information such as passwords stored in account description fields.

Reference: https://github.com/ropnop/windapsearch

Reference: https://linux.die.net/man/1/ldapsearch

We can use Python to quickly check if we can interact with LDAP without credentials.

```python
Python 3.8.5 (default, Aug  2 2020, 15:09:07) 
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from ldap3 import *
>>> s = Server('10.129.1.207',get_info = ALL)
>>> c =  Connection(s, '', '')
>>> c.bind()
True
>>> s.info
```

## Using `Ldapsearch`

We can confirm anonymous LDAP bind with ldapsearch and retrieve all AD objects from LDAP.

```
ldapsearch -H ldap://10.129.1.207 -x -b "dc=inlanefreight,dc=local"
```

## Using `Windapsearch`

`Windapsearch` is a Python script used to perform anonymous and authenticated LDAP enumeration of AD users, groups, and computers using LDAP queries. It is an alternative to tools such as `ldapsearch`, which require you to craft custom LDAP queries. We can use it to confirm LDAP NULL session authentication but providing a blank username with `-u ""` and add `--functionality` to confirm the domain functional level.

```
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" --functionality
```

We can pull a listing of all domain users to use in a password spraying attack.

```
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -U
```

We can obtain information about all domain computers.

```
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -C
```

This process can be repeated to pull group information and more detailed information such as unconstrained users and computers, GPO information, user and computer attributes, and more.

## Other Tools

There are many other tools and helper scripts for retrieving information from LDAP. This script **`ldapsearch-ad.py`** is similar to `windapsearch`.

We can use it to pull domain information and confirm a `NULL` bind. This particular tool requires valid domain user credentials to perform additional enumeration.

```
python3 ldapsearch-ad.py -l 10.129.1.207 -t info
```

# Credentialed LDAP Enumeration

As with SMB, once we have domain credentials, we can extract a wide variety of information from LDAP, including user, group, computer, trust, GPO info, the domain password policy, etc. `ldapsearch-ad.py` and `windapsearch` are useful for performing this enumeration.

## `windapsearch`

```
python3 windapsearch.py --dc-ip 10.129.1.207 -u inlanefreight\\james.cross --da
```

Some additional useful options, including pulling users and computers with unconstrained delegation.

```
python3 windapsearch.py --dc-ip 10.129.1.207 -d inlanefreight.local -u inlanefreight\\james.cross --unconstrained-users
```

## `Ldapsearch-ad`

This tool can perform all of the standard enumeration and a few built-in searches to simplify things. We can quickly obtain the password policy.

```
python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t pass-pols
```

We can look for users who may be subject to a Kerberoasting attack.

```
python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t kerberoast | grep servicePrincipalName:
```

Also, it quickly retrieves users that can be ASREPRoasted.

```
python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t asreproast
```
