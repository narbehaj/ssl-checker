# SSL Checker
#### Simple Python script that collects SSL information from hosts

## About

It's a simple script running in python that collects SSL information then it returns the group of information in JSON.

## Requirements

You only need to installl pyOpenSSL:

`pip install pyopenssl`

## Usage

`python ssl_checker.py host1[:port] [host2:port] [host3:port]...`

Port is optional here. The script will use 443 if not specified.

## Example

```bash
narbeh@narbeh-xps:~/ssl-checker$ python ssl_checker.py test.com narbeh.org:443 archive.org facebook.com:443 twitter.com github.com google.com
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