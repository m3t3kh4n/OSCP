# Git

```
git clone file:///git-server/ 
```
- Set up Git credentials
```
git config --global user.name "dademola"
git config --global user.email "dademola@hunit.(none)"
```

In `git-shell`, we should be able to interact with the repository. Let's clone this repo on our attack machine.
```
GIT_SSH_COMMAND='ssh -i id_rsa -p 43022' git clone git@192.168.120.204:/git-server
```
In `git-shell`, `push` to git server from attacker machine:
```
GIT_SSH_COMMAND='ssh -i ~/id_rsa -p 43022' git push origin master
```

---

https://medium.com/@blueclps080984/proving-grounds-hunit-intermediate-linux-box-walkthrough-a-journey-to-offensive-security-36081fc196d

---

# git-dumper
```
git-dumper <URL> .
```

Getting commits
```
git log > commits.txt; cat commits.txt | grep commit
```

File changes:
```
git log -p <last-commit>
```
