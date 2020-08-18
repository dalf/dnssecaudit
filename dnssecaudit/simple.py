# pylint: disable=invalid-name
import socket
import dns.resolver
import dns.reversename


def dns_query(qname, field):
    dns_answers = None
    dns_error = None
    try:
        dns_answers = dns.resolver.query(qname, field)
    except dns.resolver.NXDOMAIN:
        # ignore: The DNS query name does not exist.
        dns_answers = None
        dns_error = None
    except dns.resolver.NoAnswer:
        # ignore: The DNS response does not contain an answer to the question.
        dns_answers = None
        dns_error = None
    except dns.resolver.NoNameservers:
        # All nameservers failed to answer the query.
        # dns_error='No non-broken nameservers are available to answer the question'
        dns_answers = None
        dns_error = None
    except dns.exception.Timeout:
        # The DNS operation timed out.
        dns_answers = None
        dns_error = 'Timeout'
    except dns.resolver.YXDOMAIN:
        # The DNS query name is too long after DNAME substitution.
        dns_answers = None
        dns_error = 'Timeout after DNAME substitution'
    except Exception as ex:
        dns_answers = None
        dns_error = str(ex)
    return dns_answers, dns_error


def dns_query_field(host: str, field: str):
    dns_answers, dns_error = dns_query(host, field)
    return list(map(str, dns_answers or [])), dns_error


def get_info(host: str):
    result = {}
    for field_type in ['A', 'AAAA']:
        addresses, error = dns_query_field(host, field_type)
        result[field_type]=(addresses, error)
    return result
