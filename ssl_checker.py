#!/usr/bin/env python
import socket
import sys

from argparse import ArgumentParser, SUPPRESS
from datetime import datetime
from ssl import PROTOCOL_TLSv1
from time import sleep
from csv import DictWriter

try:
    from OpenSSL import SSL
except ImportError:
    print('Required module does not exist. Install: pip install pyopenssl')
    sys.exit(1)


class Clr:
    """Text colors."""

    RST = '\033[39m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'


def get_cert(host, port, user_args):
    """Connection to the host."""
    if user_args.socks:
        import socks
        socks_host, socks_port = filter_hostname(user_args.socks)
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, socks_host, int(socks_port), True)
        socket.socket = socks.socksocket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    osobj = SSL.Context(PROTOCOL_TLSv1)
    sock.connect((host, int(port)))
    oscon = SSL.Connection(osobj, sock)
    oscon.set_tlsext_host_name(host.encode())
    oscon.set_connect_state()
    oscon.do_handshake()
    cert = oscon.get_peer_certificate()
    sock.close()

    return cert


def border_msg(message):
    """Print the message in the box."""
    row = len(message)
    h = ''.join(['+'] + ['-' * row] + ['+'])
    result = h + '\n' "|" + message + "|"'\n' + h
    print(result)


def analyze_ssl(host, context):
    """Analyze the security of the SSL certificate."""
    from json import loads
    try:
        from urllib.request import urlopen
    except ImportError:
        from urllib2 import urlopen

    api_url = 'https://api.ssllabs.com/api/v3/'
    while True:
        main_request = loads(urlopen(api_url + 'analyze?host={}'.format(host)).read().decode('utf-8'))
        if main_request['status'] in ('DNS', 'IN_PROGRESS'):
            sleep(5)
            continue
        elif main_request['status'] == 'READY':
            break

    endpoint_data = loads(urlopen(api_url + 'getEndpointData?host={}&s={}'.format(
        host, main_request['endpoints'][0]['ipAddress'])).read().decode('utf-8'))

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


def get_cert_sans(x509cert):
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


def get_cert_info(host, cert):
    """Get all the information about cert and create a JSON file."""
    context = {}

    cert_subject = cert.get_subject()

    context['issued_to'] = cert_subject.CN
    context['issued_o'] = cert_subject.O
    context['issuer_c'] = cert.get_issuer().countryName
    context['issuer_o'] = cert.get_issuer().organizationName
    context['issuer_ou'] = cert.get_issuer().organizationalUnitName
    context['issuer_cn'] = cert.get_issuer().commonName
    context['cert_sn'] = cert.get_serial_number()
    context['cert_sha1'] = cert.digest('sha1').decode()
    context['cert_alg'] = cert.get_signature_algorithm().decode()
    context['cert_ver'] = cert.get_version()
    context['cert_sans'] = get_cert_sans(cert)
    context['cert_exp'] = cert.has_expired()

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

    return context


def print_status(host, context, analyze=False):
    """Print all the usefull info about host."""
    days_left = (datetime.strptime(context[host]['valid_till'], '%Y-%m-%d') - datetime.now()).days

    print('\t{}[+]{} {}\n\t{}'.format(Clr.GREEN, Clr.RST, host, '-' * (len(host) + 5)))
    print('\t\tIssued domain: {}'.format(context[host]['issued_to']))
    print('\t\tIssued to: {}'.format(context[host]['issued_o']))
    print('\t\tIssued by: {} ({})'.format(context[host]['issuer_o'], context[host]['issuer_c']))
    print('\t\tValid from: {}'.format(context[host]['valid_from']))
    print('\t\tValid to: {} ({} days left)'.format(context[host]['valid_till'], days_left))
    print('\t\tValidity days: {}'.format(context[host]['validity_days']))
    print('\t\tCertificate S/N: {}'.format(context[host]['cert_sn']))
    print('\t\tCertificate SHA1 FP: {}'.format(context[host]['cert_sha1']))
    print('\t\tCertificate version: {}'.format(context[host]['cert_ver']))
    print('\t\tCertificate algorithm: {}'.format(context[host]['cert_alg']))

    if analyze and context.get('grade', False):  # If analyze part fails
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


def show_result(user_args):
    """Get the context."""
    context = {}
    failed_cnt = 0
    start_time = datetime.now()
    hosts = user_args.hosts

    if not user_args.json_true:
        border_msg(' Analyzing {} host(s) '.format(len(hosts)))

    if not user_args.json_true and user_args.analyze:
        print('{}Warning: -a/--analyze is enabled. It takes more time...{}\n'.format(Clr.YELLOW, Clr.RST))

    for host in hosts:
        host, port = filter_hostname(host)

        # Check duplication
        if host in context.keys():
            continue

        try:
            cert = get_cert(host, port, user_args)
            context[host] = get_cert_info(host, cert)

            # Analyze the certificate if enabled
            if user_args.analyze:
                context = analyze_ssl(host, context)

            if not user_args.json_true:
                print_status(host, context, user_args.analyze)
        except Exception as error:
            if not user_args.json_true:
                print('\t{}[-]{} {:<20s} Failed: {}\n'.format(Clr.RED, Clr.RST, host, error))
                failed_cnt += 1
        except KeyboardInterrupt:
            print('{}Canceling script...{}\n'.format(Clr.YELLOW, Clr.RST))
            sys.exit(1)

    if not user_args.json_true:
        border_msg(' Successful: {} | Failed: {} | Duration: {} '.format(
            len(hosts) - failed_cnt, failed_cnt, datetime.now() - start_time))

    # CSV export if -c/--csv is specified
    if user_args.csv_enabled:
        export_csv(context, user_args.csv_enabled)

    # Enable JSON output if -j/--json argument specified
    if user_args.json_true:
        if user_args.pretty_output:
            from pprint import pprint
            pprint(context)
        else:
            print(context)


def export_csv(context, filename):
    """Export all context results to CSV file."""
    # prepend dict keys to write column headers
    with open(filename, 'w') as csv_file:
        csv_writer = DictWriter(csv_file, list(context.items())[0][1].keys())
        csv_writer.writeheader()
        for host in context.keys():
            csv_writer.writerow(context[host])


def filter_hostname(host):
    """Remove unused characters and split by address and port."""
    host = host.replace('http://', '').replace('https://', '').replace('/', '')
    port = 443
    if ':' in host:
        host, port = host.split(':')

    return host, port


def get_args():
    """Set argparse options."""
    parser = ArgumentParser(prog='ssl_checker.py', add_help=False,
                            description="""Collects useful information about given host's SSL certificates.""")

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
    parser.add_argument('-a', '--analyze', dest='analyze',
                        default=False, action='store_true',
                        help='Enable SSL security analysis on the host')
    parser.add_argument('-p', '--pretty', dest='pretty_output',
                        action='store_true', default=False,
                        help='Print pretty and more human readable JSON')
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
    show_result(get_args())
