# SSL Checker
#### Python script that collects SSL/TLS information from hosts



## About

It's a simple script running in python that collects SSL/TLS information then it returns the group of information in JSON. It can also connect through your specified SOCKS server.

One of the good things about this script is that it will fully analyze the SSL certificate for security issues and will include the report in the output, CSV, HTML, or a JSON file.



## Requirements

`pip install -r requirements.txt`



## Usage

```
./ssl_checker.py -h
usage: ssl_checker.py (-H [HOSTS [HOSTS ...]] | -f HOST_FILE) [-s HOST:PORT]
                      [-c FILENAME.CSV] [-j] [-S] [-x] [-J] [-a] [-v] [-h]

Collects useful information about given host's SSL certificates.

optional arguments:
  -H [HOSTS [HOSTS ...]], --host [HOSTS [HOSTS ...]]
                        Hosts as input separated by space
  -f HOST_FILE, --host-file HOST_FILE
                        Hosts as input from file
  -s HOST:PORT, --socks HOST:PORT
                        Enable SOCKS proxy for connection
  -c FILENAME.CSV, --csv FILENAME.CSV
                        Enable CSV file export
  -j, --json            Enable JSON in the output
  -S, --summary         Enable summary output only
  -x, --html            Enable HTML file export
  -J, --json-save       Enable JSON export individually per host
  -a, --analyze         Enable SSL security analysis on the host
  -v, --verbose         Enable verbose to see what is going on
  -h, --help            Show this help message and exit
```



Port is optional here. The script will use 443 if not specified.

`-f, --host-file` File containing hostnames for input

`-H, --host ` Enter the hosts separated by space

`-s, --socks ` Enable connection through SOCKS server

`-c, --csv ` Enable CSV file export by specifying filename.csv after this argument

`-j, --json ` Use this if you want to only have the result in JSON

`-S, --summary ` This argument will show quick summary in the output

`-x, --html ` Enable HTML file export

`-J, --json-save` Use this if you want to save as JSON file per host

`-a, --analyze` This argument will include security analyze on the certificate. Takes more time. No result means failed to analyze. 

`-v, --verbose` Shows more output. Good for troubleshooting.

`-h, --help`	Shows the help and exit



## Example

```
narbeh@narbeh-laptop:~/ssl-checker$ ./ssl_checker.py -H time.com github.com:443
+---------------------+
| Analyzing 2 host(s) |
+---------------------+
	[+] time.com
	-------------
		Issued domain: time.com
		Issued to: None
		Issued by: Amazon (US)
		Valid from: 2019-09-06
		Valid to: 2020-10-06 (78 days left)
		Validity days: 396
		Certificate valid: True
		Certificate S/N: 20641318859548253362475798736742284477
		Certificate SHA1 FP: D5:CE:1B:77:AB:59:C9:BE:37:58:0F:5D:73:97:64:98:C4:3E:43:30
		Certificate version: 2
		Certificate algorithm: sha256WithRSAEncryption
		Expired: False
		Certificate SAN's: 
		 \_ DNS:time.com
		 \_ DNS:*.time.com


	[+] github.com
	---------------
		Issued domain: github.com
		Issued to: GitHub, Inc.
		Issued by: DigiCert Inc (US)
		Valid from: 2020-05-05
		Valid to: 2022-05-10 (659 days left)
		Validity days: 735
		Certificate valid: True
		Certificate S/N: 7101927171473588541993819712332065657
		Certificate SHA1 FP: 5F:3F:7A:C2:56:9F:50:A4:66:76:47:C6:A1:8C:A0:07:AA:ED:BB:8E
		Certificate version: 2
		Certificate algorithm: sha256WithRSAEncryption
		Expired: False
		Certificate SAN's: 
		 \_ DNS:github.com
		 \_ DNS:www.github.com


+-------------------------------------------------------------------------------------------+
| Successful: 2 | Failed: 0 | Valid: 2 | Warning: 0 | Expired: 0 | Duration: 0:00:07.694433 |
+-------------------------------------------------------------------------------------------+
```

NOTE: Keep in mind that if the certificate has less than 15 days validity, the script will consider it as a warning in the summary.



## Censored?

No problem. Pass `-s/--socks` argument to the script with `HOST:PORT` format to connect through SOCKS proxy.

```
narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -H facebook.com
+-------------------+
|Analyzing 1 host(s)|
+-------------------+

	[-] facebook.com         Failed: [Errno 111] Connection refused

+-------------------------------------------------------------------------------------------+
| Successful: 0 | Failed: 1 | Valid: 0 | Warning: 0 | Expired: 0 | Duration: 0:00:04.109058 |
+-------------------------------------------------------------------------------------------+

narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -H facebook.com -s localhost:9050
+---------------------+
| Analyzing 1 host(s) |
+---------------------+
	[+] facebook.com
	-----------------
		Issued domain: *.facebook.com
		Issued to: Facebook, Inc.
		Issued by: DigiCert Inc (US)
		Valid from: 2020-05-14
		Valid to: 2020-08-05 (16 days left)
		Validity days: 83
		Certificate valid: True
		Certificate S/N: 19351530099991824979726880175805235719
		Certificate SHA1 FP: 89:7F:54:63:61:34:2F:7E:B4:B5:68:E2:92:79:D2:98:B4:97:D8:EA
		Certificate version: 2
		Certificate algorithm: sha256WithRSAEncryption
		Expired: False
		Certificate SAN's: 
		 \_ DNS:*.facebook.com
		 \_ DNS:*.facebook.net
		 \_ DNS:*.fbcdn.net
		 \_ DNS:*.fbsbx.com
		 \_ DNS:*.messenger.com
		 \_ DNS:facebook.com
		 \_ DNS:messenger.com
		 \_ DNS:*.m.facebook.com
		 \_ DNS:*.xx.fbcdn.net
		 \_ DNS:*.xy.fbcdn.net
		 \_ DNS:*.xz.fbcdn.net


+-------------------------------------------------------------------------------------------+
| Successful: 1 | Failed: 0 | Valid: 1 | Warning: 0 | Expired: 0 | Duration: 0:00:00.416188 |
+-------------------------------------------------------------------------------------------+
```



## Quick Summary

Sometimes you need to run the script and get the quick summary of the hosts. By passing `-S/--summary` you will get the quick overview of the result.

```
narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -H narbeh.org:443 test.com twitter.com -S
+-------------------------------------------------------------------------------------------+
| Successful: 3 | Failed: 0 | Valid: 3 | Warning: 0 | Expired: 0 | Duration: 0:00:01.958670 |
+-------------------------------------------------------------------------------------------+
```



## Security Analyze

By passing `-a/--analyze` to the script, it will scan the certificate for security issues and vulnerabilities. It will also mark a grade for the certificate. **This will take more time to finish.**

```
narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -H narbeh.org:443 -a
+---------------------+
| Analyzing 1 host(s) |
+---------------------+

Warning: -a/--analyze is enabled. It takes more time...

	[+] narbeh.org

		Issued domain: narbeh.org
		Issued to: None
		Issued by: Let's Encrypt (US)
		Valid from: 2018-04-21
		Valid to: 2018-07-20 (88 days left)
		Validity days: 90
		Certificate S/N: 338163108483756707389368573553026254634358
		Certificate version: 2
		Certificate algorithm: sha256WithRSAEncryption
		Certificate grade: A
		Poodle vulnerability: False
		Heartbleed vulnerability: False
		Hearbeat vulnerability: True
		Freak vulnerability: False
		Logjam vulnerability: False
		Drown vulnerability: False
		Expired: False

+------------------------------------------------------+
| Successful: 1 | Failed: 0 | Duration: 0:00:01.429145 |
+------------------------------------------------------+
```



## JSON, HTML and CSV Output

Example only with the `-j/--json` argument which shows the JSON only. Perfect for piping to another tool.

```
narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -j -H narbeh.org:443
{"narbeh.org": {"host": "narbeh.org", "issued_to": "sni.cloudflaressl.com", "issued_o": "Cloudflare, Inc.", "issuer_c": "US", "issuer_o": "CloudFlare, Inc.", "issuer_ou": null, "issuer_cn": "CloudFlare Inc ECC CA-2", "cert_sn": "20958932659753030511717961095784314907", "cert_sha1": "FC:2D:0E:FD:DE:C0:98:7D:23:D2:E7:14:4C:07:6A:3D:25:25:49:B6", "cert_alg": "ecdsa-with-SHA256", "cert_ver": 2, "cert_sans": "DNS:sni.cloudflaressl.com; DNS:narbeh.org; DNS:*.narbeh.org", "cert_exp": false, "cert_valid": true, "valid_from": "2020-04-02", "valid_till": "2020-10-09", "validity_days": 190, "days_left": 81, "valid_days_to_expire": 81, "tcp_port": 443}}
```

CSV export is also easy. After running the script with `-c/--csv` argument and specifying `filename.csv` after it, you'll have something like this:

```
narbeh@narbeh-xps:~/ssl-checker$ cat domain.csv 
narbeh.org
issued_to,narbeh.org
valid_till,2018-07-20
valid_from,2018-04-21
issuer_ou,None
cert_ver,2
cert_alg,sha256WithRSAEncryption
cert_exp,False
issuer_c,US
issuer_cn,Let's Encrypt Authority X3
issuer_o,Let's Encrypt
validity_days,90
cert_sn,338163108483756707389368573553026254634358
```

Finally, if you want to export JSON's output per host in a separated file, use `-J/--json-save`. This will export JSON's output per host. 



# As a Python Module

Simply import the `ssl_checker.py` into your python script and use it as a module.

```
from ssl_checker import SSLChecker

SSLChecker = SSLChecker()
args = {
    'hosts': ['google.com', 'cisco.com']
}

SSLChecker.show_result(SSLChecker.get_args(json_args=args))
```



# Docker

##### From the Docker Hub

```
$ docker run -it --rm narbehaj/ssl-checker -H twitter.com
```

##### Build your own Dockerfile

If you want to run this script via docker, simply do create your image and run once:

```
$ docker build -t ssl-checker .
$ docker run -it --rm ssl-checker -H twitter.com
```



## Todo

- Enable timeout for connections and handshakes
- Make print_status cleaner and smarter

