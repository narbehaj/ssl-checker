#!/usr/bin/env python3
import socket
import sys
import json
import ssl
import warnings
from datetime import datetime, timezone

from argparse import ArgumentParser, SUPPRESS
from time import sleep
from csv import DictWriter
from concurrent.futures import ThreadPoolExecutor

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
    from json2html import *
except ImportError:
    print('Please install required modules: pip install -r requirements.txt')
    sys.exit(1)


class Clr:
    """Text colors."""

    RST = '\033[39m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'


TLS_VERSIONS = [
    ('TLS 1.0', getattr(ssl.TLSVersion, 'TLSv1', None), True),
    ('TLS 1.1', getattr(ssl.TLSVersion, 'TLSv1_1', None), True),
    ('TLS 1.2', getattr(ssl.TLSVersion, 'TLSv1_2', None), False),
    ('TLS 1.3', getattr(ssl.TLSVersion, 'TLSv1_3', None), False),
]

STARTTLS_PROTOCOLS = ('smtp', 'imap', 'pop3', 'ftp', 'xmpp')


class SSLChecker:

    total_valid = 0
    total_expired = 0
    total_failed = 0
    total_warning = 0
    total_untrusted = 0

    def connect(self, host, port, user_args):
        """Open a TCP socket to the host, going through SOCKS if asked to."""
        if user_args.socks:
            import socks

            proxy_host, proxy_port = self.filter_hostname(user_args.socks)
            sock = socks.socksocket()
            sock.set_proxy(socks.PROXY_TYPE_SOCKS5, proxy_host, int(proxy_port), True)
            sock.settimeout(user_args.timeout)
            sock.connect((host, int(port)))
            return sock

        # create_connection walks every address getaddrinfo returns, so this
        # works for IPv6-only hosts too.
        return socket.create_connection((host, int(port)), user_args.timeout)

    def starttls(self, sock, protocol, host):
        """Upgrade a plaintext connection to TLS before the handshake."""
        proto = protocol.lower()

        def chat(line=None):
            if line is not None:
                sock.sendall(line.encode() + b'\r\n')
            return sock.recv(4096)

        if proto == 'smtp':
            chat()
            chat('EHLO ssl-checker')
            chat('STARTTLS')
        elif proto == 'imap':
            chat()
            chat('a001 STARTTLS')
        elif proto == 'pop3':
            chat()
            chat('STLS')
        elif proto == 'ftp':
            chat()
            chat('AUTH TLS')
        elif proto == 'xmpp':
            sock.sendall("<stream:stream xmlns='jabber:client' "
                         "xmlns:stream='http://etherx.jabber.org/streams' "
                         "to='{}' version='1.0'>".format(host).encode())
            sock.recv(4096)
            sock.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            sock.recv(4096)
        else:
            raise ValueError('Unsupported STARTTLS protocol: {}'.format(protocol))

    def handshake(self, host, port, context, user_args):
        """Do the TLS handshake and return the peer cert and connection facts.

        A dropped connection (reset/refused) gets retried; a timeout does not,
        so a dead host doesn't cost us several full timeouts in a row.
        """
        error = None
        for attempt in range(user_args.retries + 1):
            sock = self.connect(host, port, user_args)
            try:
                if user_args.starttls:
                    self.starttls(sock, user_args.starttls, host)
                tls = context.wrap_socket(sock, server_hostname=host)
            except ssl.SSLError:
                sock.close()
                raise                       # cert/protocol issue, retrying won't help
            except TimeoutError:
                sock.close()
                raise
            except OSError as err:
                sock.close()
                error = err
                sleep(0.5)
                continue

            try:
                cert = tls.getpeercert(binary_form=True)
                version = tls.version()
                cipher = tls.cipher()
                ip = 'via-proxy' if user_args.socks else tls.getpeername()[0]
                return cert, version, cipher, self.chain_length(tls), ip
            finally:
                tls.close()

        raise error

    def chain_length(self, tls):
        """How many certs the server sent, when the runtime can tell us."""
        getter = getattr(tls, 'get_unverified_chain', None)
        if getter is None:
            return None
        try:
            return len(getter() or [])
        except Exception:
            return None

    def get_cert(self, host, port, user_args):
        """Grab the certificate and work out whether it can be trusted.

        We try a full verification first. If that fails we retry without the
        hostname check (to see if only the name was wrong) and finally with no
        verification at all, so we can still report on a broken certificate.
        """
        ca_file = user_args.ca_file or None
        verify = ssl.create_default_context(cafile=ca_file)

        chain_only = ssl.create_default_context(cafile=ca_file)
        chain_only.check_hostname = False

        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE

        trusted = True
        note = None
        try:
            cert, version, cipher, chain, ip = self.handshake(host, port, verify, user_args)
        except ssl.SSLCertVerificationError as err:
            note = getattr(err, 'verify_message', None) or str(err)
            try:
                cert, version, cipher, chain, ip = self.handshake(host, port, chain_only, user_args)
            except ssl.SSLError:
                cert, version, cipher, chain, ip = self.handshake(host, port, insecure, user_args)
                trusted = False

        return {
            'cert': x509.load_der_x509_certificate(cert, default_backend()),
            'resolved_ip': ip,
            'tls_version': version,
            'cipher': cipher,
            'chain_length': chain,
            'trusted': trusted,
            'validation_error': note,
        }

    def supported_protocols(self, host, port, user_args):
        """Return a dict of TLS version -> whether the host accepts it."""
        result = {}
        for label, version, _weak in TLS_VERSIONS:
            if version is None:
                continue

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                # Pinning to an old version warns about its deprecation; that's
                # the whole point of the probe, so silence it.
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', DeprecationWarning)
                    context.minimum_version = version
                    context.maximum_version = version
            except (ValueError, OSError):
                result[label] = False          # OpenSSL refuses to even offer it
                continue

            try:
                self.handshake(host, port, context, user_args)
                result[label] = True
            except Exception:
                result[label] = False

        return result

    def host_matches_cert(self, host, cert):
        """Does host match one of the cert's names? Handles single-level wildcards."""
        names = []
        try:
            san = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            names = list(san.get_values_for_type(x509.DNSName))
        except x509.extensions.ExtensionNotFound:
            pass
        if not names:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn:
                names = [cn[0].value]

        host = host.lower().rstrip('.')
        for name in names:
            name = name.lower().rstrip('.')
            if name.startswith('*.'):
                suffix = name[1:]              # '*.foo.com' -> '.foo.com'
                if host.endswith(suffix) and host.count('.') == suffix.count('.'):
                    return True
            elif name == host:
                return True
        return False

    def public_key_info(self, cert):
        """Return (type, bits, is_weak) for the certificate's public key."""
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return 'RSA', key.key_size, key.key_size < 2048
        if isinstance(key, dsa.DSAPublicKey):
            return 'DSA', key.key_size, key.key_size < 2048
        if isinstance(key, ec.EllipticCurvePublicKey):
            return 'EC ({})'.format(key.curve.name), key.curve.key_size, key.curve.key_size < 256
        return type(key).__name__, None, False

    def border_msg(self, message):
        """Print the message in the box."""
        row = len(message)
        h = ''.join(['+'] + ['-' * row] + ['+'])
        result = h + '\n' "|" + message + "|"'\n' + h
        print(result)

    def analyze_ssl(self, host, data, user_args):
        """Pull a grade and vulnerability report for the host from SSL Labs."""
        try:
            from urllib.request import urlopen
        except ImportError:
            from urllib2 import urlopen

        api_url = 'https://api.ssllabs.com/api/v3/'
        while True:
            if user_args.verbose:
                print('{}Requesting analyze to {}{}\n'.format(Clr.YELLOW, api_url, Clr.RST))

            main_request = json.loads(urlopen(api_url + 'analyze?host={}'.format(host)).read().decode('utf-8'))
            if main_request['status'] in ('DNS', 'IN_PROGRESS'):
                if user_args.verbose:
                    print('{}Analyze waiting for reports to be finished (5 secs){}\n'.format(Clr.YELLOW, Clr.RST))

                sleep(5)
                continue
            elif main_request['status'] == 'READY':
                if user_args.verbose:
                    print('{}Analyze is ready{}\n'.format(Clr.YELLOW, Clr.RST))

                break

        endpoint_data = json.loads(urlopen(api_url + 'getEndpointData?host={}&s={}'.format(
            host, main_request['endpoints'][0]['ipAddress'])).read().decode('utf-8'))

        if user_args.verbose:
            print('{}Analyze report message: {}{}\n'.format(Clr.YELLOW, endpoint_data['statusMessage'], Clr.RST))

        # The grade only makes sense if the cert is valid for the name.
        if endpoint_data['statusMessage'] == 'Certificate not valid for domain name':
            return data

        details = endpoint_data['details']
        data['grade'] = main_request['endpoints'][0]['grade']
        data['poodle_vuln'] = details['poodle']
        data['heartbleed_vuln'] = details['heartbleed']
        data['heartbeat_vuln'] = details['heartbeat']
        data['freak_vuln'] = details['freak']
        data['logjam_vuln'] = details['logjam']
        data['drownVulnerable'] = details['drownVulnerable']
        return data

    def get_cert_sans(self, x509cert):
        """Subject Alternative Names as a single, csv-safe string."""
        san = ''
        try:
            ext = x509cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            names = [str(getattr(name, 'value', name)) for name in ext.value]
            san = '; '.join(names)
        except x509.extensions.ExtensionNotFound:
            pass

        # commas would split our csv columns
        return san.replace(',', ';')

    def get_cert_info(self, host, conn, user_args):
        """Turn a certificate into the dict we report on."""
        cert = conn['cert']
        subject = cert.subject
        issuer = cert.issuer
        context = {}

        def first(name, oid):
            attrs = name.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else 'N/A'

        context['host'] = host
        context['resolved_ip'] = conn['resolved_ip']
        context['tls_version'] = conn['tls_version']
        context['issued_to'] = first(subject, x509.NameOID.COMMON_NAME)
        context['issued_o'] = first(subject, x509.NameOID.ORGANIZATION_NAME)
        context['issuer_c'] = first(issuer, x509.NameOID.COUNTRY_NAME)
        context['issuer_o'] = first(issuer, x509.NameOID.ORGANIZATION_NAME)
        context['issuer_ou'] = first(issuer, x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
        context['issuer_cn'] = first(issuer, x509.NameOID.COMMON_NAME)
        context['cert_sn'] = str(cert.serial_number)
        context['cert_sha1'] = cert.fingerprint(hashes.SHA1()).hex()
        context['cert_sha256'] = cert.fingerprint(hashes.SHA256()).hex()
        context['cert_alg'] = cert.signature_algorithm_oid._name
        context['cert_ver'] = cert.version.value
        context['cert_sans'] = self.get_cert_sans(cert)
        context['cert_exp'] = cert.not_valid_after_utc < datetime.now(timezone.utc)

        key_type, key_bits, weak_key = self.public_key_info(cert)
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'N/A'
        context['pub_key_type'] = key_type
        context['pub_key_bits'] = key_bits
        context['sig_hash'] = sig_hash
        context['weak_key'] = weak_key
        context['weak_sig'] = sig_hash.lower() in ('sha1', 'md5')

        context['cipher'] = conn['cipher'][0] if conn['cipher'] else None
        context['chain_length'] = conn['chain_length']
        context['cert_trusted'] = conn['trusted']
        context['hostname_valid'] = self.host_matches_cert(host, cert)
        context['self_signed'] = subject == issuer
        context['validation_error'] = conn['validation_error']

        # "valid" means it is in date, the chain checks out and the name matches.
        context['cert_valid'] = (not context['cert_exp'] and context['cert_trusted']
                                 and context['hostname_valid'])

        context['valid_from'] = cert.not_valid_before_utc.strftime('%Y-%m-%d')
        context['valid_till'] = cert.not_valid_after_utc.strftime('%Y-%m-%d')
        context['validity_days'] = (cert.not_valid_after_utc - cert.not_valid_before_utc).days

        now = datetime.now(timezone.utc)
        context['days_left'] = (cert.not_valid_after_utc - now).days
        context['valid_days_to_expire'] = context['days_left']
        return context

    def check_host(self, host, port, user_args):
        """Everything we do for a single host. Returns the dict or 'failed'."""
        try:
            conn = self.get_cert(host, port, user_args)
            data = self.get_cert_info(host, conn, user_args)
            data['tcp_port'] = int(port)

            if user_args.protocols:
                offered = self.supported_protocols(host, port, user_args)
                data['supported_protocols'] = offered
                data['weak_protocols'] = [label for label, _v, weak in TLS_VERSIONS
                                          if weak and offered.get(label)]

            if user_args.analyze:
                self.analyze_ssl(host, data, user_args)

            return data, None
        except ssl.SSLError:
            return 'failed', 'Misconfigured SSL/TLS'
        except Exception as error:
            return 'failed', str(error)

    def has_problem(self, data, warning_days):
        """True if the host is worth flagging (used by --quiet)."""
        if data == 'failed':
            return True
        return not data['cert_valid'] or data['valid_days_to_expire'] <= warning_days

    def print_status(self, host, data, user_args):
        """Print everything we know about one host."""
        ok = lambda flag: '{}{}{}'.format(Clr.GREEN if flag else Clr.RED, flag, Clr.RST)

        print('\t{}[✓]{} {}\n\t{}'.format(
            Clr.GREEN if data['cert_valid'] else Clr.RED, Clr.RST, host, '-' * (len(host) + 5)))
        print('\t\tIssued domain: {}'.format(data['issued_to']))
        print('\t\tIssued to: {}'.format(data['issued_o']))
        print('\t\tIssued by: {} ({})'.format(data['issuer_o'], data['issuer_c']))
        print('\t\tServer IP: {}'.format(data['resolved_ip']))
        print('\t\tValid from: {}'.format(data['valid_from']))
        print('\t\tValid to: {} ({} days left)'.format(data['valid_till'], data['valid_days_to_expire']))
        print('\t\tValidity days: {}'.format(data['validity_days']))
        print('\t\tTLS Version: {}'.format(data['tls_version']))
        print('\t\tCipher: {}'.format(data['cipher']))
        print('\t\tChain length: {}'.format(data['chain_length']))
        print('\t\tCertificate trusted: {}'.format(ok(data['cert_trusted'])))
        print('\t\tHostname matches: {}'.format(ok(data['hostname_valid'])))
        if data['self_signed']:
            print('\t\t{}Self-signed certificate{}'.format(Clr.YELLOW, Clr.RST))
        if data['validation_error']:
            print('\t\t{}Validation note: {}{}'.format(Clr.YELLOW, data['validation_error'], Clr.RST))
        print('\t\tCertificate valid: {}'.format(data['cert_valid']))
        print('\t\tCertificate S/N: {}'.format(data['cert_sn']))
        print('\t\tCertificate SHA1 FP: {}'.format(data['cert_sha1']))
        print('\t\tCertificate SHA256 FP: {}'.format(data['cert_sha256']))
        print('\t\tCertificate version: {}'.format(data['cert_ver']))
        print('\t\tCertificate algorithm: {}'.format(data['cert_alg']))

        key = '{} {} bits'.format(data['pub_key_type'], data['pub_key_bits']) if data['pub_key_bits'] \
            else data['pub_key_type']
        if data['weak_key']:
            key += ' {}(weak){}'.format(Clr.RED, Clr.RST)
        print('\t\tPublic key: {}'.format(key))
        sig = data['sig_hash'] + (' {}(weak){}'.format(Clr.RED, Clr.RST) if data['weak_sig'] else '')
        print('\t\tSignature hash: {}'.format(sig))

        if 'supported_protocols' in data:
            offered = [label for label, on in data['supported_protocols'].items() if on]
            print('\t\tSupported protocols: {}'.format(', '.join(offered) if offered else 'none'))
            if data['weak_protocols']:
                print('\t\t{}Weak protocols enabled: {}{}'.format(
                    Clr.RED, ', '.join(data['weak_protocols']), Clr.RST))

        if user_args.analyze:
            print('\t\tCertificate grade: {}'.format(data.get('grade')))
            print('\t\tPoodle vulnerability: {}'.format(data.get('poodle_vuln')))
            print('\t\tHeartbleed vulnerability: {}'.format(data.get('heartbleed_vuln')))
            print('\t\tHeartbeat vulnerability: {}'.format(data.get('heartbeat_vuln')))
            print('\t\tFreak vulnerability: {}'.format(data.get('freak_vuln')))
            print('\t\tLogjam vulnerability: {}'.format(data.get('logjam_vuln')))
            print('\t\tDrown vulnerability: {}'.format(data.get('drownVulnerable')))

        print('\t\tExpired: {}'.format(data['cert_exp']))
        print('\t\tCertificate SANs: ')
        for san in data['cert_sans'].split(';'):
            print('\t\t \\_ {}'.format(san.strip()))
        print('\n')

    def show_result(self, user_args):
        """Run the checks for every host and print/return the result."""
        context = {}
        start_time = datetime.now(timezone.utc)
        text_output = not user_args.json_true and not user_args.summary_true

        # Split host:port and drop duplicates, keeping the original order.
        hosts = []
        seen = set()
        for raw in user_args.hosts:
            host, port = self.filter_hostname(raw)
            if host not in seen:
                seen.add(host)
                hosts.append((host, port))

        concurrency = max(1, getattr(user_args, 'concurrency', 1))
        if user_args.socks and concurrency > 1:
            if not user_args.json_true:
                print('{}SOCKS proxy is global; running one host at a time.{}\n'.format(Clr.YELLOW, Clr.RST))
            concurrency = 1

        if text_output:
            self.border_msg(' Analyzing {} host(s) '.format(len(hosts)))
        if not user_args.json_true and user_args.analyze:
            print('{}Warning: -a/--analyze is enabled. It takes more time...{}\n'.format(Clr.YELLOW, Clr.RST))

        def work(item):
            host, port = item
            if user_args.verbose:
                print('{}Working on host: {}{}\n'.format(Clr.YELLOW, host, Clr.RST))
            return (host, port) + self.check_host(host, port, user_args)

        try:
            if concurrency > 1:
                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    results = list(pool.map(work, hosts))
            else:
                results = [work(item) for item in hosts]
        except KeyboardInterrupt:
            print('{}Canceling script...{}\n'.format(Clr.YELLOW, Clr.RST))
            sys.exit(1)

        # Tally and print on the main thread, so the counters stay sane.
        for host, port, data, error in results:
            context[host] = data
            if data == 'failed':
                self.total_failed += 1
                if text_output:
                    print('\t{}[✗]{} {:<20s} Failed: {}\n'.format(Clr.RED, Clr.RST, host, error))
                continue

            if data['cert_exp']:
                self.total_expired += 1
            else:
                self.total_valid += 1
            if not data['cert_trusted']:
                self.total_untrusted += 1
            if not data['cert_exp'] and data['valid_days_to_expire'] <= user_args.warning_days:
                self.total_warning += 1

            if text_output and (not user_args.quiet or self.has_problem(data, user_args.warning_days)):
                self.print_status(host, data, user_args)

        if not user_args.json_true:
            self.border_msg(' Successful: {} | Failed: {} | Valid: {} | Warning: {} | '
                            'Expired: {} | Untrusted: {} | Duration: {} '.format(
                                len(hosts) - self.total_failed, self.total_failed, self.total_valid,
                                self.total_warning, self.total_expired, self.total_untrusted,
                                datetime.now(timezone.utc) - start_time))

        if user_args.csv_enabled:
            self.export_csv(context, user_args.csv_enabled, user_args)
        if user_args.html_true:
            self.export_html(context)

        # When imported as a module, hand the data back as JSON.
        if __name__ != '__main__':
            return json.dumps(context)

        if user_args.json_true:
            print(json.dumps(context))
        if user_args.json_save_true:
            for host in context.keys():
                with open(host + '.json', 'w', encoding='UTF-8') as fp:
                    fp.write(json.dumps(context[host]))

        if getattr(user_args, 'exit_code', False):
            sys.exit(self.exit_status())

    def exit_status(self):
        """Nagios-style code: 2 critical, 1 warning, 0 healthy."""
        if self.total_failed or self.total_expired or self.total_untrusted:
            return 2
        if self.total_warning:
            return 1
        return 0

    def export_csv(self, context, filename, user_args):
        """Write every result to a CSV file."""
        if user_args.verbose:
            print('{}Generating CSV export{}\n'.format(Clr.YELLOW, Clr.RST))

        # Collect the columns from every host so an extra flag (e.g. -p) on one
        # host doesn't drop its columns from the file.
        columns = []
        for data in context.values():
            if isinstance(data, dict):
                for key in data:
                    if key not in columns:
                        columns.append(key)

        with open(filename, 'w') as csv_file:
            if not columns:
                writer = DictWriter(csv_file, ['host', 'status'])
                writer.writeheader()
                for host in context:
                    writer.writerow({'host': host, 'status': 'failed'})
                return

            writer = DictWriter(csv_file, columns, extrasaction='ignore')
            writer.writeheader()
            for host, data in context.items():
                if not isinstance(data, dict):
                    writer.writerow({'host': host, **{c: 'failed' for c in columns if c != 'host'}})
                    continue
                row = dict(data)
                for key, value in row.items():
                    if isinstance(value, (dict, list)):
                        row[key] = json.dumps(value).replace(',', ';')
                writer.writerow(row)

    def export_html(self, context):
        """Dump the results to a timestamped HTML file."""
        html = json2html.convert(json=context)
        file_name = datetime.strftime(datetime.now(timezone.utc), '%Y_%m_%d_%H_%M_%S')
        with open('{}.html'.format(file_name), 'w') as html_file:
            html_file.write(html)

    def filter_hostname(self, host):
        """Strip the scheme/slashes and split off the port (defaults to 443)."""
        host = host.replace('http://', '').replace('https://', '').replace('/', '')
        port = 443
        if ':' in host:
            host, port = host.split(':')

        return host, port

    def read_host_file(self, path):
        """Read hosts from a file (or stdin with '-'), ignoring blanks/comments."""
        if path == '-':
            lines = sys.stdin.read().splitlines()
        else:
            with open(path) as f:
                lines = f.read().splitlines()

        return [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]

    def get_args(self, json_args={}):
        """Set argparse options."""
        parser = ArgumentParser(prog='ssl_checker.py', add_help=False,
                                description="""Collects useful information about the given host's SSL certificates.""")

        # Module use: take the host list (and optional knobs) and use defaults
        # for the rest.
        if len(json_args) > 0:
            args = parser.parse_args([])
            defaults = {
                'json_true': True, 'verbose': False, 'csv_enabled': False, 'html_true': False,
                'json_save_true': False, 'socks': False, 'analyze': False, 'summary_true': False,
                'quiet': False, 'exit_code': False, 'ca_file': None,
                'protocols': json_args.get('protocols', False),
                'starttls': json_args.get('starttls', None),
                'concurrency': json_args.get('concurrency', 1),
                'warning_days': json_args.get('warning_days', 15),
                'timeout': json_args.get('timeout', 5),
                'retries': json_args.get('retries', 2),
            }
            for key, value in defaults.items():
                setattr(args, key, value)
            args.hosts = json_args['hosts']
            return args

        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-H', '--host', dest='hosts', nargs='*',
                           required=False, help='Hosts as input separated by space')
        group.add_argument('-f', '--host-file', dest='host_file',
                           required=False, help="Hosts from a file ('-' reads stdin)")
        parser.add_argument('-s', '--socks', dest='socks',
                            default=False, metavar='HOST:PORT',
                            help='Enable SOCKS proxy for connection')
        parser.add_argument('-c', '--csv', dest='csv_enabled',
                            default=False, metavar='FILENAME.CSV',
                            help='Enable CSV file export')
        parser.add_argument('-j', '--json', dest='json_true',
                            action='store_true', default=False,
                            help='Enable JSON in the output')
        parser.add_argument('-S', '--summary', dest='summary_true',
                            action='store_true', default=False,
                            help='Enable summary output only')
        parser.add_argument('-x', '--html', dest='html_true',
                            action='store_true', default=False,
                            help='Enable HTML file export')
        parser.add_argument('-J', '--json-save', dest='json_save_true',
                            action='store_true', default=False,
                            help='Enable JSON export individually per host')
        parser.add_argument('-t', '--timeout', dest='timeout',
                            type=int, default=5,
                            help='Timeout for the connection in seconds (default: 5)')
        parser.add_argument('-r', '--retries', dest='retries',
                            type=int, default=2, metavar='N',
                            help='Retries on a dropped connection (default: 2)')
        parser.add_argument('-a', '--analyze', dest='analyze',
                            default=False, action='store_true',
                            help='Enable SSL security analysis on the host')
        parser.add_argument('-p', '--protocols', dest='protocols',
                            default=False, action='store_true',
                            help='Probe which TLS versions (1.0-1.3) the host accepts')
        parser.add_argument('-T', '--starttls', dest='starttls',
                            default=None, metavar='PROTO', choices=STARTTLS_PROTOCOLS,
                            help='Use STARTTLS first (smtp/imap/pop3/ftp/xmpp)')
        parser.add_argument('--ca-file', dest='ca_file',
                            default=None, metavar='FILE',
                            help='Verify against this CA bundle instead of the system store')
        parser.add_argument('-n', '--concurrency', dest='concurrency',
                            type=int, default=1, metavar='N',
                            help='Number of hosts to check in parallel (default: 1)')
        parser.add_argument('-w', '--warning-days', dest='warning_days',
                            type=int, default=15, metavar='DAYS',
                            help='Days-to-expiry threshold for a warning (default: 15)')
        parser.add_argument('-q', '--quiet', dest='quiet',
                            default=False, action='store_true',
                            help='Only print hosts that have a problem')
        parser.add_argument('-e', '--exit-code', dest='exit_code',
                            default=False, action='store_true',
                            help='Exit non-zero for monitoring (1=warning, 2=critical)')
        parser.add_argument('-v', '--verbose', dest='verbose',
                            default=False, action='store_true',
                            help='Enable verbose to see what is going on')
        parser.add_argument('-h', '--help', default=SUPPRESS,
                            action='help',
                            help='Show this help message and exit')

        args = parser.parse_args()

        if args.host_file:
            args.hosts = self.read_host_file(args.host_file)

        if isinstance(args.hosts, list) and len(args.hosts) == 0:
            parser.print_help()
            sys.exit(0)

        return args


if __name__ == '__main__':
    SSLCheckerObject = SSLChecker()
    SSLCheckerObject.show_result(SSLCheckerObject.get_args(json_args={}))
