# Linux Privilege Escallation

- [ ] Writable `/etc/shadow`
- [ ] Writable `/etc/passwd`
- [ ] Check user's history
- [ ] Check user's `env`
- [ ] Check user's `.bashrc`
- [ ] SUID Bit
- [ ] `sudo -l`
- [ ] Cron Job
- [ ] Get the usernames from `/home` start brute force for the users
- [ ] If you come from web check `config.php`
- [ ] Look for services like `mysql`
- [ ] Look for internal ports
- [ ] Password Reuse (get password from different resources like db, config files and reuse them)
- [ ] Username and the password the same like `patrick:patrick`
- [ ] Create a key pair using `ssh-keygen` command and then change `id_rsa.pub` file to `authorized_keys` and add this file
- [ ] Check group of the user: if it is fail2ban group [fail2ban PrivEsc](https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7) (PG-Practice Fail)
