# SSL Checker
#### Simple Python script that collects SSL information from hosts

#About

It's a simple script running in python that collects SSL information then it returns the group of information in JSON.

# Requirements

You only need to installl pyOpenSSL:

`pip install pyopenssl`

# Usage

`python ssl_checker.py host1 [host2] [host3]...`

# Example

```bash
narbeh@narbeh-xps:~/ssl-checker$ python ssl_checker.py cisco.com archive.org ttttessssttt.com
Analyzing 3 hosts:

	[+] cisco.com
	[+] archive.org
	[-] ttttessssttt.com failed: [Errno -2] Name or service not known

3 successful and 1 failed.

{'archive.org': {'valid_till': '2020-02-21', 'valid_from': '2016-12-19', 'cert_alg': u'sha256WithRSAEncryption', 'cert_ver': 2, 'cert_sn': 17565460289571369468L, 'cert_exp': False, 'issuer_c': u'US', 'issuer_cn': u'Go Daddy Secure Certificate Authority - G2', 'issuer_o': u'GoDaddy.com, Inc.', 'issuer_ou': u'http://certs.godaddy.com/repository/'}, 'cisco.com': {'valid_till': '2019-12-07', 'valid_from': '2017-12-07', 'cert_alg': u'sha256WithRSAEncryption', 'cert_ver': 2, 'cert_sn': 228799876318721608922476410131646115852301898990L, 'cert_exp': False, 'issuer_c': u'US', 'issuer_cn': u'HydrantID SSL ICA G2', 'issuer_o': u'HydrantID (Avalanche Cloud Corporation)', 'issuer_ou': None}}
```



