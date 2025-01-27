1. If the server doesn't let you crate any kind of `.php` extensions to upload. Does this:
2. We create our own .htaccess file that outlines a NEW PHP file type and upload it.
```
echo "AddType application/x-httpd-php .dork" > .htaccess
```
3. Then apply your malicious `filename.dork` to the server.
