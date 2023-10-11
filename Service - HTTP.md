
# Checklist
- [ ] Check robots.txt
- [ ] Check sitemap.xml
- [ ] Check HTML Source Code
- [ ] Check custom CSS
- [ ] Check custom JS
- [ ] Check Headers
- [ ] Check Responses
- [ ] Crawl Website
- [ ] Create MindMap tree
- [ ] get hostname from SSL certificate
- [ ] Check Comments 
- [ ] Gobuster
- [ ] Wapplyzer
- [ ] Nikto -> `nikto -h http://ip`
- [ ] Whatweb
- [ ] Subdomains
- [ ] Virtual Hosts
- [ ] Sometimes Burp Suite doesn't gives response, use `curl`, `wget`, `nc` in this case.
- [ ] Check different methods for suspicious pages like `GET`, `POST`, `PUT`, `HEAD`, `OPTIONS`, `PATCH`, `DELETE`
- [ ] If you find `LFI` check for `RFI` too (if there is a no chance to upload file anyway)
- [ ] cewl passwords
- [ ] Check cookies
- [ ] SSTI if there is a Node.js app
- [ ] Check `phpinfo.php`. If it is available, then there is a chance to look for SQL Injection. By this way you can see the location of www from `phpinfo.php` file and you can write into while to the defined location and get webshell [CHECK](https://github.com/m3t3kh4n/OSCP/blob/main/SQL%20Injection.md#into-outfile-method-payloadallthethings).
- [ ] Check directory with the name of the box like `/Name`.
- [ ] If there are users, photos and descriptions under them, grab usernames (generally check for different name or description or photo), also descriptions can be passwords.
- [ ] XSS for stealing Administrator cookies
- [ ] CSRF for executing some commands on behalf of Administrator
- [ ] See URL place try \\<your-ip>\random share for NTLM Relay and LLMNR Poisoning
- [ ] Getting NTLM
  - [ ] File upload file URL as a share
  - [ ] JS `src` as a share
  - [ ] Command Injection
  - [ ] `impacket-smbserver sharename $(pwd) -smb2support`
- [ ] Download images and `exiftool` to look for juicy information like username
- [ ] Get emails for username

# `gobuster`
- Using Basic Auth
```
gobuster dir -u http://192.168.85.46:242/ -w /usr/share/dirb/wordlists/common.txt -k -x .txt,.php --threads 50 -U offsec -P elite
```

## Top

```
sitemap.xml
robots.txt
api/
.git
```

# SQL Injection
1. Single quote check
2. `ORDER BY`
3. `UNION`
4. `user()`
5. `system_user()`
6. `@@datadir`
7. `LOAD_FILE('c:/windows32/system32/license.rtf')`
8. xp cmd (MS SQL)

