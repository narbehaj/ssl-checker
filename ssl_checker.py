#!/usr/bin/env python
import socket
import sys

from ssl import create_default_context
from datetime import datetime


class TextColor:
    """Text colors."""

    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RESET = '\033[39m'


def get_cert(host, port):
    """Connection to the host."""
    sslctx = create_default_context()
    sock = sslctx.wrap_socket(socket.socket(), server_hostname=host)

    try:
        sock.connect((host, int(port)))
        print('\t{}[+]{} {}'.format(TextColor.GREEN, TextColor.RESET, host))
    except Exception as e:
        print('\t{}[-]{} {} failed: {}'.format(TextColor.RED, TextColor.RESET, host, e))
        return None

    cert = sock.getpeercert()
    sock.close()
    return cert


def get_cert_info(cert):
    """Get all the information about cert and create a JSON file."""
    context = {}

    issued_to = dict(x[0] for x in cert['subject'])
    issued_by = dict(x[0] for x in cert['issuer'])

    context['issuer_c'] = issued_by['countryName']
    context['issuer_o'] = issued_by['organizationName']
    context['issuer_cn'] = issued_by['commonName']
    context['issued_to'] = issued_to['commonName']
    context['cert_sn'] = cert['serialNumber']
    context['cert_ver'] = cert['version']

    # Valid from
    valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
    context['valid_from'] = valid_from.strftime('%Y-%m-%d')

    # Vali till
    valid_till = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    context['valid_till'] = valid_till.strftime('%Y-%m-%d')

    # Validity days
    context['validity_days'] = (valid_till - valid_from).days

    # Expiry check
    context['expired'] = False if valid_till >= datetime.now() else True

    return context


def show_result(hosts):
    """Get the context."""
    context= {}
    failed_cnt, total_cnt = 0, 0
    print('Analyzing {} hosts:\n'.format(len(hosts)))
    for host in hosts:
        host, port = filter_hostname(host)
        cert = get_cert(host, port)
        if cert:
            context[host] = get_cert_info(cert)
        else:
            failed_cnt += 1

    print('\n{} successful and {} failed.'.format(len(hosts) - failed_cnt, failed_cnt))

    print(context)


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
