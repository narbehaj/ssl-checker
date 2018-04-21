#!/usr/bin/env python
import socket
import sys
from pprint import pprint
from argparse import ArgumentParser, SUPPRESS
from datetime import datetime
from ssl import PROTOCOL_TLSv1

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


def get_cert(host, port):
    """Connection to the host."""
    osobj = SSL.Context(PROTOCOL_TLSv1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, int(port)))
    oscon = SSL.Connection(osobj, sock)
    oscon.set_tlsext_host_name(host.encode())
    oscon.set_connect_state()
    oscon.do_handshake()
    cert = oscon.get_peer_certificate()
    sock.close()

    return cert


def get_cert_info(cert):
    """Get all the information about cert and create a JSON file."""
    context = {}

    context['issuer_c'] = cert.get_issuer().countryName
    context['issuer_o'] = cert.get_issuer().organizationName
    context['issuer_ou'] = cert.get_issuer().organizationalUnitName
    context['issuer_cn'] = cert.get_issuer().commonName
    context['cert_sn'] = cert.get_serial_number()
    context['cert_alg'] = cert.get_signature_algorithm().decode()
    context['cert_ver'] = cert.get_version()
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


def show_result(user_args):
    """Get the context."""
    context = {}
    failed_cnt = 0
    hosts = user_args.hosts

    if not user_args.json_true:
        print('Analyzing {} hosts:\n'.format(len(hosts)))

    for host in hosts:
        host, port = filter_hostname(host)

        # Check duplication
        if host in context.keys():
            continue

        try:
            cert = get_cert(host, port)
            context[host] = get_cert_info(cert)
            if not user_args.json_true:
                print('\t{}[+]{} {:<20s} Expired: {}'.format(Clr.GREEN, Clr.RST, host, context[host]['cert_exp']))
        except Exception as error:
            if not user_args.json_true:
                print('\t{}[-]{} {:<20s} Failed: {}'.format(Clr.RED, Clr.RST, host, error))

            failed_cnt += 1

    if not user_args.json_true:
        print('\n{} successful and {} failed\n'.format(len(hosts) - failed_cnt, failed_cnt))

    # Enable JSON output if -j argument specified
    if user_args.json_true:
        if user_args.pretty_output:
            pprint(context)
        else:
            print(context)

def filter_hostname(host):
    """Remove unused characters and split by address and port."""
    host = host.replace('http://', '').replace('https://', '').replace('/', '')
    port = 443
    if ':' in host:
        host, port = host.split(':')

    return host, port


def get_args():
    """Set argparse options."""
    parser = ArgumentParser(prog='ssl_checker.py', add_help=False)
    parser.add_argument("-H", "--host", dest="hosts", nargs='*', required=True,
                        help="Hosts as input separated by space")
    parser.add_argument("-j", "--json", dest="json_true",
                        action="store_true", default=False,
                        help="Enable JSON in the output")
    parser.add_argument("-p", "--pretty", dest="pretty_output",
                        action="store_true",default=False,
                        help="Print pretty and more human readable Json")
    parser.add_argument("-h", "--help", default=SUPPRESS,
                        action='help',
                        help='Show this help message and exit')

    args = parser.parse_args()

    # Checks hosts list
    if isinstance(args.hosts, list):
        if len(args.hosts) == 0:
            parser.print_help()
            sys.exit(0)

    return args


if __name__ == '__main__':
    show_result(get_args())
