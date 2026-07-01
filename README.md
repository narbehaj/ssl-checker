# Python SSL/TLS Checker
#### Python script that collects SSL/TLS information from hosts



## About

It's a swiss-army script running in Python that collects SSL/TLS information from endpoints and returns the group of information as human-readable text, JSON, CSV, or HTML. It can also connect through your specified SOCKS server.

Highlights:

- **Real validation** — verifies the certificate chain against the system trust store and checks that the hostname actually matches the certificate (with wildcard support), so you can tell *expired*, *untrusted*, *self-signed*, and *wrong-host* apart.
- **Correct protocol/cipher reporting** — reports the *actually negotiated* TLS version and cipher suite (TLS 1.3 aware).
- **Protocol enumeration** (`-p`) — probes which of TLS 1.0–1.3 an endpoint accepts and flags the insecure ones still enabled.
- **Weak-config detection** — flags weak public keys (RSA/DSA < 2048-bit) and weak signature hashes (SHA-1/MD5).
- **STARTTLS** (`-T`) — inspect certificates on SMTP, IMAP, POP3, FTP, and XMPP endpoints, not just HTTPS.
- **Parallel scanning** (`-n`) — check many hosts concurrently.
- **Monitoring mode** (`-e`, `-q`) — Nagios-style exit codes (`1` = warning, `2` = critical) and a quiet mode that only prints hosts with a problem.
- **SSL Labs analysis** (`-a`) — optional deep scan for known vulnerabilities and a letter grade.
- **Resilient by default** — IPv4/IPv6, automatic retries on dropped connections, host lists from a file or stdin (blank lines and `#` comments ignored), and an optional custom CA bundle (`--ca-file`).


## Requirements

`pip install -r requirements.txt`

Or by pip installation:

`pip install python-ssl-checker`

## Usage

```
./ssl_checker.py -h
usage: ssl_checker.py (-H [HOSTS ...] | -f HOST_FILE) [-s HOST:PORT]
                      [-c FILENAME.CSV] [-j] [-S] [-x] [-J] [-t TIMEOUT]
                      [-r N] [-a] [-p] [-T PROTO] [--ca-file FILE] [-n N]
                      [-w DAYS] [-q] [-e] [-v] [-h]

Collects useful information about the given host's SSL certificates.

options:
  -H, --host [HOSTS ...]
                        Hosts as input separated by space
  -f, --host-file HOST_FILE
                        Hosts from a file ('-' reads stdin)
  -s, --socks HOST:PORT
                        Enable SOCKS proxy for connection
  -c, --csv FILENAME.CSV
                        Enable CSV file export
  -j, --json            Enable JSON in the output
  -S, --summary         Enable summary output only
  -x, --html            Enable HTML file export
  -J, --json-save       Enable JSON export individually per host
  -t, --timeout TIMEOUT
                        Timeout for the connection in seconds (default: 5)
  -r, --retries N       Retries on a dropped connection (default: 2)
  -a, --analyze         Enable SSL security analysis on the host
  -p, --protocols       Probe which TLS versions (1.0-1.3) the host accepts
  -T, --starttls PROTO  Use STARTTLS first (smtp/imap/pop3/ftp/xmpp)
  --ca-file FILE        Verify against this CA bundle instead of the system
                        store
  -n, --concurrency N   Number of hosts to check in parallel (default: 1)
  -w, --warning-days DAYS
                        Days-to-expiry threshold for a warning (default: 15)
  -q, --quiet           Only print hosts that have a problem
  -e, --exit-code       Exit non-zero for monitoring (1=warning, 2=critical)
  -v, --verbose         Enable verbose to see what is going on
  -h, --help            Show this help message and exit
```


The port is optional here. The script will use 443 if not specified.

`-f, --host-file` File containing hostnames for input. Use `-` to read the list from stdin. Blank lines and lines starting with `#` are ignored, so you can keep a commented host list.

`-H, --host ` Enter the hosts separated by space

`-s, --socks ` Enable connection through the SOCKS server

`-c, --csv ` Enable CSV file export by specifying filename.csv after this argument

`-j, --json ` Use this if you want only to have the result in JSON

`-S, --summary ` This argument will show a quick summary of the output

`-x, --html ` Enable HTML file export

`-J, --json-save` Use this if you want to save as JSON file per host

`-t, --timeout TIMEOUT` Timeout for the connection in seconds (default: 5)

`-r, --retries N` How many times to retry a dropped connection (reset/refused) before giving up (default: 2). Timeouts are not retried, so an unreachable host won't stall for several timeouts in a row.

`-a, --analyze` This argument will include security analysis on the certificate. Takes more time. No result means failure to analyze. 

`--ca-file FILE` Verify the certificate chain against the CA bundle in `FILE` instead of the operating system trust store. Handy for internal/private CAs.

`-q, --quiet` Only print hosts that have a problem (expired, untrusted, wrong hostname, failed, or expiring within `--warning-days`). The summary line is still shown. Great for noisy host lists.

`-p, --protocols` Probe each of TLS 1.0–1.3 individually and report which versions the endpoint accepts. Versions that are still enabled but considered insecure (TLS 1.0/1.1) are highlighted as weak.

`-T, --starttls PROTO` Upgrade a plaintext connection with STARTTLS before inspecting the certificate. Supports `smtp`, `imap`, `pop3`, `ftp`, and `xmpp`. Remember to point the port at the right service, e.g. `-H mail.example.com:587 -T smtp`.

`-n, --concurrency N` Check up to N hosts in parallel. Great for scanning a large `--host-file`. (Forced to 1 when `-s/--socks` is used, since the proxy uses global state.)

`-w, --warning-days DAYS` Number of days before expiry that counts as a warning (default: 15). Affects the summary and the `-e` exit code.

`-e, --exit-code` Return a monitoring-friendly exit code: `0` = all good, `1` = at least one certificate is expiring within `--warning-days`, `2` = at least one host failed, expired, or is untrusted. Ideal for cron jobs and CI pipelines.

`-v, --verbose` Shows more output. Good for troubleshooting.

`-h, --help`	Shows the help and exit



## Example

```
narbeh@narbeh-laptop:~/ssl-checker$ ./ssl_checker.py -H time.com github.com:443
+---------------------+
| Analyzing 2 host(s) |
+---------------------+
	[✓] time.com
	-------------
		Issued domain: time.com
		Issued to: None
		Issued by: Amazon (US)
		Valid from: 2019-09-06
		Valid to: 2020-10-06 (78 days left)
		Validity days: 396
		TLS Version: TLS 1.2
		Certificate valid: True
		Certificate S/N: 20641318859548253362475798736742284477
		Certificate SHA1 FP: D5:CE:1B:77:AB:59:C9:BE:37:58:0F:5D:73:97:64:98:C4:3E:43:30
		Certificate version: 2
		Certificate algorithm: sha256WithRSAEncryption
		Expired: False
		Certificate SANs: 
		 \_ DNS:time.com
		 \_ DNS:*.time.com


	[✓] github.com
	---------------
		Issued domain: github.com
		Issued to: GitHub, Inc.
		Issued by: DigiCert Inc (US)
		Valid from: 2020-05-05
		Valid to: 2022-05-10 (659 days left)
		Validity days: 735
		TLS Version: TLS 1.2
		Certificate valid: True
		Certificate S/N: 7101927171473588541993819712332065657
		Certificate SHA1 FP: 5F:3F:7A:C2:56:9F:50:A4:66:76:47:C6:A1:8C:A0:07:AA:ED:BB:8E
		Certificate version: 2
		Certificate algorithm: sha256WithRSAEncryption
		Expired: False
		Certificate SANs: 
		 \_ DNS:github.com
		 \_ DNS:www.github.com


+-------------------------------------------------------------------------------------------+
| Successful: 2 | Failed: 0 | Valid: 2 | Warning: 0 | Expired: 0 | Duration: 0:00:07.694433 |
+-------------------------------------------------------------------------------------------+
```

NOTE: Keep in mind that if the certificate has less than 15 days of validity, the script will consider it as a warning in the summary.

## Censored?

No problem. Pass `-s/--socks` argument to the script with `HOST:PORT` format to connect through the SOCKS proxy.

```
narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -H facebook.com
+-------------------+
|Analyzing 1 host(s)|
+-------------------+

	[✗] facebook.com         Failed: [Errno 111] Connection refused

+-------------------------------------------------------------------------------------------+
| Successful: 0 | Failed: 1 | Valid: 0 | Warning: 0 | Expired: 0 | Duration: 0:00:04.109058 |
+-------------------------------------------------------------------------------------------+

narbeh@narbeh-xps:~/ssl-checker$ ./ssl_checker.py -H facebook.com -s localhost:9050
+---------------------+
| Analyzing 1 host(s) |
+---------------------+
	[✓] facebook.com
	-----------------
		Issued domain: *.facebook.com
		Issued to: Facebook, Inc.
		Issued by: DigiCert Inc (US)
		Valid from: 2020-05-14
		Valid to: 2020-08-05 (16 days left)
		Validity days: 83
		TLS Version: TLS 1.2
		Certificate valid: True
		Certificate S/N: 19351530099991824979726880175805235719
		Certificate SHA1 FP: 89:7F:54:63:61:34:2F:7E:B4:B5:68:E2:92:79:D2:98:B4:97:D8:EA
		Certificate version: 2
		Certificate algorithm: sha256WithRSAEncryption
		Expired: False
		Certificate SANs: 
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

Sometimes you need to run the script and get a quick summary of the hosts. You will get a quick overview of the result by passing `-S/--summary`.

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

	[✓] narbeh.org

		Issued domain: narbeh.org
		Issued to: None
		Issued by: Let's Encrypt (US)
		Valid from: 2018-04-21
		Valid to: 2018-07-20 (88 days left)
		Validity days: 90
		TLS Version: TLS 1.2
		Certificate S/N: 338163108483756707389368573553026254634358
		Certificate version: 2
		Certificate algorithm: sha256WithRSAEncryption
		Certificate grade: A
		Poodle vulnerability: False
		Heartbleed vulnerability: False
		Heartbeat vulnerability: True
		Freak vulnerability: False
		Logjam vulnerability: False
		Drown vulnerability: False
		Expired: False

+------------------------------------------------------+
| Successful: 1 | Failed: 0 | Duration: 0:00:01.429145 |
+------------------------------------------------------+
```



## Certificate Validation

Unlike a plain "is it expired?" check, the script tells you *why* a certificate is good or bad. Every host reports whether the chain is **trusted** by your system trust store and whether the **hostname matches** the certificate (wildcards included):

```
$ ./ssl_checker.py -H wrong.host.badssl.com self-signed.badssl.com
	[✗] wrong.host.badssl.com
		Certificate trusted: True
		Hostname matches: False
		Validation note: Hostname mismatch, certificate is not valid for 'wrong.host.badssl.com'.
		Certificate valid: False

	[✗] self-signed.badssl.com
		Certificate trusted: False
		Hostname matches: True
		Self-signed certificate
		Validation note: self-signed certificate
		Certificate valid: False
```

`Certificate valid` is `True` only when the cert is not expired **and** the chain is trusted **and** the hostname matches. The output also reports the public-key type/size and signature hash, flagging weak keys (RSA/DSA < 2048-bit) and weak hashes (SHA-1/MD5).


## Protocol Enumeration

Pass `-p/--protocols` to find out exactly which TLS versions an endpoint will accept and to catch legacy protocols that should be disabled:

```
$ ./ssl_checker.py -H github.com -p
		TLS Version: TLSv1.3
		Cipher: TLS_AES_128_GCM_SHA256
		...
		Supported protocols: TLS 1.2, TLS 1.3
```

If a host still accepts TLS 1.0 or 1.1, they are listed under `Weak protocols enabled`.


## STARTTLS (Mail / FTP / XMPP)

HTTPS isn't the only thing using certificates. Use `-T/--starttls` to inspect the certificate on a mail or FTP server that upgrades a plaintext connection:

```
$ ./ssl_checker.py -H smtp.gmail.com:587 -T smtp
	[✓] smtp.gmail.com
		Issued by: Google Trust Services (US)
		TLS Version: TLSv1.3
		Certificate trusted: True
		Hostname matches: True
```

Supported protocols: `smtp`, `imap`, `pop3`, `ftp`, `xmpp`.


## Monitoring (Exit Codes) and Concurrency

For scheduled checks, combine a host file (or `-` for stdin), parallel scanning, quiet output, and a monitoring exit code:

```
$ ./ssl_checker.py -f hosts.txt -n 20 -w 30 -q -e
+-------------------------------------------------------------------------------------------------------------+
| Successful: 50 | Failed: 0 | Valid: 50 | Warning: 2 | Expired: 0 | Untrusted: 0 | Duration: 0:00:03.114520 |
+-------------------------------------------------------------------------------------------------------------+
$ echo $?
1
```

Exit codes: `0` healthy, `1` something expires within `--warning-days`, `2` something failed/expired/untrusted. Drop it straight into cron:

```cron
0 7 * * * /path/to/ssl_checker.py -f /etc/ssl-hosts.txt -w 21 -e -S || mail -s "SSL warning" you@example.com
```


## JSON, HTML, and CSV Output

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

Finally, if you want to export JSON's output per host in a separate file, use `-J/--json-save`. This will export JSON's output per host. 

# As a Python Module

Install with pip or import the `ssl_checker.py` into your Python script and use it as a module.

`pip install python-ssl-checker`

```python
from ssl_checker import SSLChecker

SSLChecker = SSLChecker()
args = {
    'hosts': ['google.com', 'cisco.com']
}

SSLChecker.show_result(SSLChecker.get_args(json_args=args))
```

# Docker

##### From the Docker Hub

```shell
$ docker run -it --rm narbehaj/ssl-checker -H twitter.com
```

##### Build your own Dockerfile

If you want to run this script via docker, create your image and run it once:

```shell
$ docker build -t ssl-checker .
$ docker run -it --rm ssl-checker -H twitter.com
```



## Todo

- Make print_status cleaner and smarter
- OCSP / CRL revocation checking
- Optional per-cipher enumeration (not just per-protocol)
