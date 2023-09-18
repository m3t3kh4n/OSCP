
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
- [ ] 

## Top

```
sitemap.xml
robots.txt
api/
.git
```
