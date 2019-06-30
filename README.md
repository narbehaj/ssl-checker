# SSL Checker
#### Python script that collects SSL information from hosts

## About

It's a simple script running in python that collects SSL information then it returns the group of information in JSON. It can also connects trough your specified SOCKS server. 

One of the good thing about this script, is that it will full analyze the SSL certificate for security issue's and will include the report in the output or CSV file.

## Requirements

You only need to installl pyOpenSSL:

`pip install pyopenssl`

## Usage

```
./ssl_checker.py -h
usage: ssl_checker.py [-H [HOSTS [HOSTS ...]] | -f HOST_FILE] [-s HOST:PORT]
                      [-c FILENAME.CSV] [-j] [-a] [-p] [-h]

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
  -a, --analyze         Enable SSL security analysis on the host.
  -p, --pretty          Print pretty and more human readable Json
  -h, --help            Show this help message and exit
```



Port is optional here. The script will use 443 if not specified.

`-f, --host-file` File containing hostnames for input

`-H, --host ` Enter the hosts separated by space

`-s, --socks ` Enable connection through SOCKS server

`-c, --csv ` Enable CSV file export by specifying filename.csv after this argument

`-j, --json ` Use this if you want to only have the result in JSON

`-a, --analyze` This argument will include security analyze on the certificate. Takes more time. No result means failed to analyze. 

`-p, --pretty ` Use this with `-j` to print indented and human readable JSON

`-h, --help`	Shows the help and exit

## Censored?

No problem. Pass `-s/--socks` argument to the script with `HOST:PORT` format to connect through SOCKS proxy.

```
narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -H facebook.com
+-------------------+
|Analyzing 1 host(s)|
+-------------------+

	[-] facebook.com         Failed: [Errno 111] Connection refused

+------------------------------------------------------+
| Successful: 0 | Failed: 1 | Duration: 0:00:00.710470 |
+------------------------------------------------------+

narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -H facebook.com -s localhost:9050
+-------------------+
|Analyzing 1 host(s)|
+-------------------+

	[+] facebook.com

		Issued domain: *.facebook.com
		Issued by: DigiCert Inc
		Valid from: 2017-12-15
		Valid to: 2019-03-22 (334 days left)
		Validity days: 462
		Certificate S/N: 14934250041293165463321169237204988608
		Certificate version: 2
		Certificate algorithm: sha256WithRSAEncryption
		Expired: False

+------------------------------------------------------+
| Successful: 1 | Failed: 0 | Duration: 0:00:00.710470 |
+------------------------------------------------------+

```




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
		Valid from: 2018-11-07
		Valid to: 2019-12-07 (159 days left)
		Validity days: 395
		Certificate S/N: 10018094209647532371913518187860771165
		Certificate SHA1 FP: 64:C4:2E:AF:38:2A:28:64:A0:A8:B8:6B:02:05:86:1F:E7:F6:E5:FF
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
		Valid from: 2018-05-08
		Valid to: 2020-06-03 (338 days left)
		Validity days: 757
		Certificate S/N: 13324412563135569597699362973539517727
		Certificate SHA1 FP: CA:06:F5:6B:25:8B:7A:0D:4F:2B:05:47:09:39:47:86:51:15:19:84
		Certificate version: 2
		Certificate algorithm: sha256WithRSAEncryption
		Expired: False
		Certificate SAN's: 
		 \_ DNS:github.com
		 \_ DNS:www.github.com

+------------------------------------------------------+
| Successful: 2 | Failed: 0 | Duration: 0:00:01.429145 |
+------------------------------------------------------+
```



## Security Analyze

By passing `-a/--analyze` to the script, it will scan the certificate for security issues and vulnerabilities. It will also mark a grade for the certificate. **This will take more time to finish.**

```
narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -j -p -H  narbeh.org:443 -a
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



## JSON And CSV Output

Example only with the `-j/--json` and `-p/--pretty` arguments which shows the JSON only. Perfect for piping to another tool.

```
narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -j -p -H  narbeh.org:443 test.com
{'narbeh.org': {'cert_alg': u'sha256WithRSAEncryption',
                'cert_exp': False,
                'cert_sn': 338163108483756707389368573553026254634358L,
                'cert_ver': 2,
                'issued_o': None,
                'issued_to': u'narbeh.org',
                'issuer_c': u'US',
                'issuer_cn': u"Let's Encrypt Authority X3",
                'issuer_o': u"Let's Encrypt",
                'issuer_ou': None,
                'valid_from': '2018-04-21',
                'valid_till': '2018-07-20',
                'validity_days': 90},
 'test.com': {'cert_alg': u'sha256WithRSAEncryption',
              'cert_exp': False,
              'cert_sn': 73932709062103623902948514363737041075L,
              'cert_ver': 2,
              'issued_o': None,
              'issued_to': u'www.test.com',
              'issuer_c': u'US',
              'issuer_cn': u'Network Solutions DV Server CA 2',
              'issuer_o': u'Network Solutions L.L.C.',
              'issuer_ou': None,
              'valid_from': '2017-01-15',
              'valid_till': '2020-01-24',
              'validity_days': 1104}}
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



## Todo

- Enable timeout for connections and handshakes
- HTML export ability
- Make print_status cleaner and smarter


### Author

Narbeh Arakil
http://narbeh.org
