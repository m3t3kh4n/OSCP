# RSH (Remote Shell)

- (TCP) port number 514 

As an example of rsh use, the following executes the command mkdir testdir as user remoteuser on the computer host.example.com running a UNIX-like system:
```
rsh -l remoteuser host.example.com "mkdir testdir"
```
