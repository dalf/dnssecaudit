import logging

from collections import OrderedDict

import dns.exception, dns.name
from dnsviz.analysis import TTLAgnosticOfflineDomainNameAnalysis, DNS_RAW_VERSION
from dnsviz.format import latin1_binary_to_string as lb2s
from dnsviz.util import get_trusted_keys, get_default_trusted_keys
from dnsviz.viz.dnssec import DNSAuthGraph


STATUS_MAP = {
    'SECURE': '✔️',
    'BOGUS': '!',
    'INSECURE': '-',
    'NON_EXISTENT': '-',
    'VALID': '.',
    'INDETERMINATE': '-',
    'INDETERMINATE_NO_DNSKEY': '-',
    'INDETERMINATE_MATCH_PRE_REVOKE': '-',
    'INDETERMINATE_UNKNOWN_ALGORITHM': '?',
    'ALGORITHM_IGNORED': '-',
    'EXPIRED': '!',
    'PREMATURE': '!',
    'INVALID_SIG': '!',
    'INVALID': '!',
    'INVALID_DIGEST': '!',
    'INCOMPLETE': '?',
    'LAME': '?',
    'INVALID_TARGET': '!',
    'ERROR': '!',
    'WARNING': '?',
}


def _errors_warnings_full(warnings, errors, indent):
    # display status, errors, and warnings
    s = ''
    for error in errors:
        s += '%sE:%s\n' % (indent, error)

    for warning in warnings:
        s += '%sW:%s\n' % (indent, warning)

    return s


def _errors_warnings_str(status, warnings, errors):
    # display status, errors, and warnings
    error_str = ''
    if errors:
        error_str = 'ERROR'
    elif warnings:
        error_str = 'WARNING'
    return '[%-10s%-8s]' % (status, error_str)


def _textualize_status_output_response(rdtype_str, status, warnings, errors, rdata, children, depth):
    s = ''

    response_prefix = '  %(status)s%(preindent)s %(indent)s%(rdtype)s: '
    response_rdata = '%(rdata)s%(status_rdata)s'
    join_str_template = ', '

    params = {}

    # display status, errors, and warnings
    params['status'] = _errors_warnings_str(status, warnings, errors)
    params['preindent'] = ' '
    params['indent'] = '  '*depth
    params['rdtype'] = rdtype_str
    
    s += response_prefix % params

    rdata_set = []
    subwarnings_all = warnings[:]
    suberrors_all = errors[:]
    for i, (substatus, subwarnings, suberrors, rdata_item) in enumerate(rdata):
        params['rdata'] = rdata_item
        # display status, errors, and warnings
        if substatus is not None:
            params['status_rdata'] = ' ' + _errors_warnings_str(substatus, subwarnings, suberrors)
        else:
            params['status_rdata'] = ''
        rdata_set.append(response_rdata % params)

        subwarnings_all.extend(subwarnings)
        suberrors_all.extend(suberrors)

    join_str = join_str_template % params
    s += join_str.join(rdata_set) + '\n'

    s += _errors_warnings_full(subwarnings_all, suberrors_all, '        ' + params['preindent'] + params['indent'])

    for rdtype_str_child, status_child, warnings_child, errors_child, rdata_child, children_child in children:
        s += _textualize_status_output_response(rdtype_str_child, status_child, warnings_child, errors_child, rdata_child, children_child, depth + 1)

    return s


def _textualize_status_output_name(name, zone_status, zone_warnings, zone_errors, delegation_status, delegation_warnings, delegation_errors, responses):
    s = ''

    name_template = '%(name)s%(status_rdata)s\n'

    params = {}

    warnings_all = zone_warnings + delegation_warnings
    errors_all = zone_errors + delegation_errors

    params['name'] = name
    params['status_rdata'] = ''
    if zone_status is not None:
        params['status_rdata'] += ' Zone:' + _errors_warnings_str(zone_status, zone_warnings, zone_errors)
    if delegation_status is not None:
        params['status_rdata'] += ' Delegation:' + _errors_warnings_str(delegation_status, delegation_warnings, delegation_errors)
    s += name_template % params

    s += _errors_warnings_full(warnings_all, errors_all, '  ')

    for rdtype_str, status, warnings, errors, rdata, children in responses:
        s += _textualize_status_output_response(rdtype_str, status, warnings, errors, rdata, children, 0)

    return s


def textualize_status_output(names):
    s = ''
    for name, zone_status, zone_warnings, zone_errors, delegation_status, delegation_warnings, delegation_errors, responses in names:
        s += _textualize_status_output_name(name, zone_status, zone_warnings, zone_errors, delegation_status, delegation_warnings, delegation_errors, responses)

    return s


def finish_graph(G, name_objs, rdtypes, trusted_keys, supported_algs, filename):
    G.add_trust(trusted_keys, supported_algs=supported_algs)

    tuples = []
    processed = set()
    for name_obj in name_objs:
        name_obj.populate_response_component_status(G)
        tuples.extend(name_obj.serialize_status_simple(rdtypes, processed))

    print(textualize_status_output(tuples))


def print_result(analysis_structured):
    latest_analysis_date = None
    name_objs = []
    cache = {}
    names = OrderedDict()

    strict_cookies = False
    allow_private = False
    supported_digest_algs = None
    supported_algs = None
    rdtypes = None

    args = analysis_structured['_meta._dnsviz.']['names']

    for name in args:
        try:
            name = dns.name.from_text(name)
        except UnicodeDecodeError as e:
            logger.error('%s: "%s"' % (e, name))
        except dns.exception.DNSException:
            logger.error('The domain name was invalid: "%s"' % name)
        else:
            if name not in names:
                names[name] = None

    for name in names:
        name_str = lb2s(name.canonicalize().to_text())
        if name_str not in analysis_structured or analysis_structured[name_str].get('stub', True):
            logger.error('The analysis of "%s" was not found in the input.' % lb2s(name.to_text()))
            continue
        name_obj = TTLAgnosticOfflineDomainNameAnalysis.deserialize(name, analysis_structured, cache, strict_cookies=strict_cookies, allow_private=allow_private)
        name_objs.append(name_obj)

        if latest_analysis_date is None or latest_analysis_date > name_obj.analysis_end:
            latest_analysis_date = name_obj.analysis_end

    print(latest_analysis_date)
    trusted_keys = get_default_trusted_keys(latest_analysis_date)

    G = DNSAuthGraph()
    for name_obj in name_objs:
        name_obj.populate_status(trusted_keys, supported_algs=supported_algs, supported_digest_algs=supported_digest_algs)
        for qname, rdtype in name_obj.queries:
            if rdtypes is None:
                # if rdtypes was not specified, then graph all, with some
                # exceptions
                if name_obj.is_zone() and rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV):
                    continue
            else:
                # if rdtypes was specified, then only graph rdtypes that
                # were specified
                if qname != name_obj.name or rdtype not in rdtypes:
                    continue
            G.graph_rrset_auth(name_obj, qname, rdtype)

        if rdtypes is not None:
            for rdtype in rdtypes:
                if (name_obj.name, rdtype) not in name_obj.queries:
                    logger.error('No query for "%s/%s" was included in the analysis.' % (lb2s(name_obj.name.to_text()), dns.rdatatype.to_text(rdtype)))

    finish_graph(G, name_objs, rdtypes, trusted_keys, supported_algs, None)
