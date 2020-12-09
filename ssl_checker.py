#!/usr/bin/env python3
import socket
import sys
import json

from argparse import ArgumentParser, SUPPRESS
from datetime import datetime
from ssl import PROTOCOL_TLSv1
from time import sleep
from csv import DictWriter

try:
    from OpenSSL import SSL
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


class SSLChecker:

    total_valid = 0
    total_expired = 0
    total_failed = 0
    total_warning = 0

    def get_cert(self, host, port, user_args):
        """Connection to the host."""
        if user_args.socks:
            import socks
            if user_args.verbose:
                print('{}Socks proxy enabled{}\n'.format(Clr.YELLOW, Clr.RST))

            socks_host, socks_port = self.filter_hostname(user_args.socks)
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, socks_host, int(socks_port), True)
            socket.socket = socks.socksocket

        if user_args.verbose:
            print('{}Connecting to socket{}\n'.format(Clr.YELLOW, Clr.RST))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        osobj = SSL.Context(PROTOCOL_TLSv1)
        sock.connect((host, int(port)))
        oscon = SSL.Connection(osobj, sock)
        oscon.set_tlsext_host_name(host.encode())
        oscon.set_connect_state()
        oscon.do_handshake()
        cert = oscon.get_peer_certificate()
        sock.close()
        if user_args.verbose:
            print('{}Closing socket{}\n'.format(Clr.YELLOW, Clr.RST))

        return cert

    def border_msg(self, message):
        """Print the message in the box."""
        row = len(message)
        h = ''.join(['+'] + ['-' * row] + ['+'])
        result = h + '\n' "|" + message + "|"'\n' + h
        print(result)

    def analyze_ssl(self, host, context, user_args):
        """Analyze the security of the SSL certificate."""
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

        # if the certificate is invalid
        if endpoint_data['statusMessage'] == 'Certificate not valid for domain name':
            return context

        context[host]['grade'] = main_request['endpoints'][0]['grade']
        context[host]['poodle_vuln'] = endpoint_data['details']['poodle']
        context[host]['heartbleed_vuln'] = endpoint_data['details']['heartbleed']
        context[host]['heartbeat_vuln'] = endpoint_data['details']['heartbeat']
        context[host]['freak_vuln'] = endpoint_data['details']['freak']
        context[host]['logjam_vuln'] = endpoint_data['details']['logjam']
        context[host]['drownVulnerable'] = endpoint_data['details']['drownVulnerable']

        return context

    def get_cert_sans(self, x509cert):
        """
        Get Subject Alt Names from Certificate. Shameless taken from stack overflow:
        https://stackoverflow.com/users/4547691/anatolii-chmykhalo
        """
        san = ''
        ext_count = x509cert.get_extension_count()
        for i in range(0, ext_count):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        # replace commas to not break csv output
        san = san.replace(',', ';')
        return san

    def get_cert_info(self, host, cert):
        """Get all the information about cert and create a JSON file."""
        context = {}

        cert_subject = cert.get_subject()

        context['host'] = host
        context['issued_to'] = cert_subject.CN
        context['issued_o'] = cert_subject.O
        context['issuer_c'] = cert.get_issuer().countryName
        context['issuer_o'] = cert.get_issuer().organizationName
        context['issuer_ou'] = cert.get_issuer().organizationalUnitName
        context['issuer_cn'] = cert.get_issuer().commonName
        context['cert_sn'] = str(cert.get_serial_number())
        context['cert_sha1'] = cert.digest('sha1').decode()
        context['cert_alg'] = cert.get_signature_algorithm().decode()
        context['cert_ver'] = cert.get_version()
        context['cert_sans'] = self.get_cert_sans(cert)
        context['cert_exp'] = cert.has_expired()
        context['cert_valid'] = False if cert.has_expired() else True

        # Valid from
        valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_from'] = valid_from.strftime('%Y-%m-%d')

        # Valid till
        valid_till = datetime.strptime(cert.get_notAfter().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_till'] = valid_till.strftime('%Y-%m-%d')

        # Validity days
        context['validity_days'] = (valid_till - valid_from).days

        # Validity in days from now
        now = datetime.now()
        context['days_left'] = (valid_till - now).days

        # Valid days left
        context['valid_days_to_expire'] = (datetime.strptime(context['valid_till'],
                                           '%Y-%m-%d') - datetime.now()).days

        if cert.has_expired():
            self.total_expired += 1
        else:
            self.total_valid += 1

        # If the certificate has less than 15 days validity
        if context['valid_days_to_expire'] <= 15:
            self.total_warning += 1

        return context

    def print_status(self, host, context, analyze=False):
        """Print all the usefull info about host."""
        print('\t{}[+]{} {}\n\t{}'.format(Clr.GREEN, Clr.RST, host, '-' * (len(host) + 5)))
        print('\t\tIssued domain: {}'.format(context[host]['issued_to']))
        print('\t\tIssued to: {}'.format(context[host]['issued_o']))
        print('\t\tIssued by: {} ({})'.format(context[host]['issuer_o'], context[host]['issuer_c']))
        print('\t\tValid from: {}'.format(context[host]['valid_from']))
        print('\t\tValid to: {} ({} days left)'.format(context[host]['valid_till'], context[host]['valid_days_to_expire']))
        print('\t\tValidity days: {}'.format(context[host]['validity_days']))
        print('\t\tCertificate valid: {}'.format(context[host]['cert_valid']))
        print('\t\tCertificate S/N: {}'.format(context[host]['cert_sn']))
        print('\t\tCertificate SHA1 FP: {}'.format(context[host]['cert_sha1']))
        print('\t\tCertificate version: {}'.format(context[host]['cert_ver']))
        print('\t\tCertificate algorithm: {}'.format(context[host]['cert_alg']))

        if analyze:
            print('\t\tCertificate grade: {}'.format(context[host]['grade']))
            print('\t\tPoodle vulnerability: {}'.format(context[host]['poodle_vuln']))
            print('\t\tHeartbleed vulnerability: {}'.format(context[host]['heartbleed_vuln']))
            print('\t\tHeartbeat vulnerability: {}'.format(context[host]['heartbeat_vuln']))
            print('\t\tFreak vulnerability: {}'.format(context[host]['freak_vuln']))
            print('\t\tLogjam vulnerability: {}'.format(context[host]['logjam_vuln']))
            print('\t\tDrown vulnerability: {}'.format(context[host]['drownVulnerable']))

        print('\t\tExpired: {}'.format(context[host]['cert_exp']))
        print('\t\tCertificate SAN\'s: ')

        for san in context[host]['cert_sans'].split(';'):
            print('\t\t \\_ {}'.format(san.strip()))

        print('\n')

    def show_result(self, user_args):
        """Get the context."""
        context = {}
        start_time = datetime.now()
        hosts = user_args.hosts

        if not user_args.json_true and not user_args.summary_true:
            self.border_msg(' Analyzing {} host(s) '.format(len(hosts)))

        if not user_args.json_true and user_args.analyze:
            print('{}Warning: -a/--analyze is enabled. It takes more time...{}\n'.format(Clr.YELLOW, Clr.RST))

        for host in hosts:
            if user_args.verbose:
                print('{}Working on host: {}{}\n'.format(Clr.YELLOW, host, Clr.RST))

            host, port = self.filter_hostname(host)

            # Check duplication
            if host in context.keys():
                continue

            try:
                cert = self.get_cert(host, port, user_args)
                context[host] = self.get_cert_info(host, cert)
                context[host]['tcp_port'] = int(port)

                # Analyze the certificate if enabled
                if user_args.analyze:
                    context = self.analyze_ssl(host, context, user_args)

                if not user_args.json_true and not user_args.summary_true:
                    self.print_status(host, context, user_args.analyze)
            except SSL.SysCallError:
                if not user_args.json_true:
                    print('\t{}[-]{} {:<20s} Failed: Misconfigured SSL/TLS\n'.format(Clr.RED, Clr.RST, host))
                    self.total_failed += 1
            except Exception as error:
                if not user_args.json_true:
                    print('\t{}[-]{} {:<20s} Failed: {}\n'.format(Clr.RED, Clr.RST, host, error))
                    self.total_failed += 1
            except KeyboardInterrupt:
                print('{}Canceling script...{}\n'.format(Clr.YELLOW, Clr.RST))
                sys.exit(1)

        if not user_args.json_true:
            self.border_msg(' Successful: {} | Failed: {} | Valid: {} | Warning: {} | Expired: {} | Duration: {} '.format(
                len(hosts) - self.total_failed, self.total_failed, self.total_valid,
                self.total_warning, self.total_expired, datetime.now() - start_time))
            if user_args.summary_true:
                # Exit the script just
                return

        # CSV export if -c/--csv is specified
        if user_args.csv_enabled:
            self.export_csv(context, user_args.csv_enabled, user_args)

        # HTML export if -x/--html is specified
        if user_args.html_true:
            self.export_html(context)

        # While using the script as a module
        if __name__ != '__main__':
            return json.dumps(context)

        # Enable JSON output if -j/--json argument specified
        if user_args.json_true:
            print(json.dumps(context))

        if user_args.json_save_true:
            for host in context.keys():
                with open(host + '.json', 'w', encoding='UTF-8') as fp:
                    fp.write(json.dumps(context[host]))

    def export_csv(self, context, filename, user_args):
        """Export all context results to CSV file."""
        # prepend dict keys to write column headers
        if user_args.verbose:
            print('{}Generating CSV export{}\n'.format(Clr.YELLOW, Clr.RST))

        with open(filename, 'w') as csv_file:
            csv_writer = DictWriter(csv_file, list(context.items())[0][1].keys())
            csv_writer.writeheader()
            for host in context.keys():
                csv_writer.writerow(context[host])

    def export_html(self, context):
        """Export JSON to HTML."""
        html = json2html.convert(json=context)
        file_name = datetime.strftime(datetime.now(), '%Y_%m_%d_%H_%M_%S')
        with open('{}.html'.format(file_name), 'w') as html_file:
            html_file.write(html)

        return

    def filter_hostname(self, host):
        """Remove unused characters and split by address and port."""
        host = host.replace('http://', '').replace('https://', '').replace('/', '')
        port = 443
        if ':' in host:
            host, port = host.split(':')

        return host, port

    def get_args(self, json_args={}):
        """Set argparse options."""
        parser = ArgumentParser(prog='ssl_checker.py', add_help=False,
                                description="""Collects useful information about given host's SSL certificates.""")

        if len(json_args) > 0:
            args = parser.parse_args()
            setattr(args, 'json_true', True)
            setattr(args, 'verbose', False)
            setattr(args, 'csv_enabled', False)
            setattr(args, 'html_true', False)
            setattr(args, 'json_save_true', False)
            setattr(args, 'socks', False)
            setattr(args, 'analyze', False)
            setattr(args, 'hosts', json_args['hosts'])
            return args

        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-H', '--host', dest='hosts', nargs='*',
                           required=False, help='Hosts as input separated by space')
        group.add_argument('-f', '--host-file', dest='host_file',
                           required=False, help='Hosts as input from file')
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
        parser.add_argument('-a', '--analyze', dest='analyze',
                            default=False, action='store_true',
                            help='Enable SSL security analysis on the host')
        parser.add_argument('-v', '--verbose', dest='verbose',
                            default=False, action='store_true',
                            help='Enable verbose to see what is going on')
        parser.add_argument('-h', '--help', default=SUPPRESS,
                            action='help',
                            help='Show this help message and exit')

        args = parser.parse_args()

        # Get hosts from file if provided
        if args.host_file:
            with open(args.host_file) as f:
                args.hosts = f.read().splitlines()

        # Checks hosts list
        if isinstance(args.hosts, list):
            if len(args.hosts) == 0:
                parser.print_help()
                sys.exit(0)

        return args


if __name__ == '__main__':
    SSLCheckerObject = SSLChecker()
    SSLCheckerObject.show_result(SSLCheckerObject.get_args(json_args={}))
