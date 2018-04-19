#!/usr/bin/env python
import socket
import sys

from pprint import pprint
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


def show_result(hosts):
    """Get the context."""
    context = {}
    failed_cnt = 0
    print('Analyzing {} hosts:\n'.format(len(hosts)))
    for host in hosts:
        host, port = filter_hostname(host)

        # Check duplication
        if host in context.keys():
            continue

        try:
            cert = get_cert(host, port)
            context[host] = get_cert_info(cert)
            print('\t{}[+]{} {:<20s} Expired: {}'.format(Clr.GREEN, Clr.RST, host, context[host]['cert_exp']))
        except Exception as error:
            print('\t{}[-]{} {:<20s} Failed: {}'.format(Clr.RED, Clr.RST, host, error))
            failed_cnt += 1

    print('\n{} successful and {} failed\n'.format(len(hosts) - failed_cnt, failed_cnt))

    pprint(context)


def filter_hostname(host):
    """Remove unused characters and split by address and port."""
    host = host.replace('http://', '').replace('https://', '').replace('/', '')
    port = 443
    if ':' in host:
        host, port = host.split(':')

    return host, port


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python {} host1 [host2] [host3] ...'.format(sys.argv[0]))
        sys.exit(0)

    show_result(sys.argv[1:])
