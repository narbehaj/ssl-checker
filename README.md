# SSL Checker
#### Simple Python script that collects SSL information from hosts

## About

It's a simple script running in python that collects SSL information then it returns the group of information in JSON.

## Requirements

You only need to installl pyOpenSSL:

`pip install pyopenssl`

## Usage

```
./ssl_checker.py -h
usage: ssl_checker.py -H [HOSTS [HOSTS ...]] [-j] [-h]

optional arguments:
  -H [HOSTS [HOSTS ...]], --host [HOSTS [HOSTS ...]]
                        Hosts as input separated by space
  -j, --json            Enable JSON in the output
  -p, --pretty          Print pretty and more human readable Json
  -h, --help            Show this help message and exit
```



Port is optional here. The script will use 443 if not specified.

`-j, --json`	Use this if you want to only have the result in JSON

`-p, --pretty` Use this with `-j` to print indented and human readable json

`-H, --host`	Enter the hosts separated by space

`-h, --help` Shows the help and exit


## Example

```
narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -H test.com narbeh.org:443 archive.org facebook.com:443 twitter.com github.com google.com
Analyzing 7 hosts:

	[+] test.com             Expired: False
	[+] narbeh.org           Expired: False
	[+] archive.org          Expired: False
	[-] facebook.com         Failed: [Errno 111] Connection refused
	[-] twitter.com          Failed: [Errno 111] Connection refused
	[+] github.com           Expired: False
	[+] google.com           Expired: False

5 successful and 2 failed
```


Example only with the `-j` and `-p` arguments which shows the JSON only. Perfect for piping to another tool.

```
narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -j -p -H test.com narbeh.org:443
{'narbeh.org': {'cert_alg': u'sha256WithRSAEncryption',
                'cert_exp': False,
                'cert_sn': 319510066429286596971677345373584681421772L,
                'cert_ver': 2,
                'issuer_c': u'US',
                'issuer_cn': u"Let's Encrypt Authority X3",
                'issuer_o': u"Let's Encrypt",
                'issuer_ou': None,
                'valid_from': '2018-02-17',
                'valid_till': '2018-05-18',
                'validity_days': 90},
 'test.com': {'cert_alg': u'sha256WithRSAEncryption',
              'cert_exp': False,
              'cert_sn': 73932709062103623902948514363737041075L,
              'cert_ver': 2,
              'issuer_c': u'US',
              'issuer_cn': u'Network Solutions DV Server CA 2',
              'issuer_o': u'Network Solutions L.L.C.',
              'issuer_ou': None,
              'valid_from': '2017-01-15',
              'valid_till': '2020-01-24',
              'validity_days': 1104}}
```
