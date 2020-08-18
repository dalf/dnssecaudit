import logging
from collections import OrderedDict

import dns.exception, dns.name
from dnsviz.analysis import TTLAgnosticOfflineDomainNameAnalysis, DNS_RAW_VERSION
from dnsviz.format import latin1_binary_to_string as lb2s
from dnsviz.util import get_trusted_keys, get_default_trusted_keys
from dnsviz.viz.dnssec import DNSAuthGraph


STATUS_VALUES = set(['SECURE', 'BOGUS', 'INSECURE', 'NON_EXISTENT', 'VALID', 'INDETERMINATE', 'INDETERMINATE_NO_DNSKEY',
    'INDETERMINATE_MATCH_PRE_REVOKE', 'INDETERMINATE_UNKNOWN_ALGORITHM', 'ALGORITHM_IGNORED', 'EXPIRED', 'PREMATURE',
    'INVALID_SIG', 'INVALID', 'INVALID_DIGEST', 'INCOMPLETE', 'LAME', 'INVALID_TARGET', 'ERROR', 'WARNING'])


logger = logging.getLogger()


def _errors_warnings_full(status, warnings, errors):
    result = OrderedDict()
    result['<status>'] = status
    if warnings:
        result['<warnings>'] = warnings
    if errors:
        result['<errors>'] = errors
    return result


def _textualize_status_output_response(rdtype_str, status, warnings, errors, rdata, children, depth):
    result = _errors_warnings_full(status, warnings, errors)

    result['<rdata>'] = {}
    rdata_set = []
    for i, (substatus, subwarnings, suberrors, rdata_item) in enumerate(rdata):
        result['<rdata>'][rdata_item] = _errors_warnings_full(substatus, subwarnings, suberrors)

    result['<rdtype>'] = {}
    for rdtype_str_child, status_child, warnings_child, errors_child, rdata_child, children_child in children:
        result['<rdtype>'][rdtype_str] = _textualize_status_output_response(rdtype_str_child, status_child, warnings_child, errors_child, rdata_child, children_child, depth + 1)

    return result


def _textualize_status_output_name(name, zone_status, zone_warnings, zone_errors, delegation_status, delegation_warnings, delegation_errors, responses):
    result = OrderedDict()

    if zone_status is not None:
        result['<zone>'] = _errors_warnings_full(zone_status, zone_warnings, zone_errors)
    if delegation_status is not None:
        result['<delegation>'] = _errors_warnings_full(delegation_status, delegation_warnings, delegation_errors)

    for rdtype_str, status, warnings, errors, rdata, children in responses:
        result[rdtype_str] = _textualize_status_output_response(rdtype_str, status, warnings, errors, rdata, children, 0)

    return {name: result}


def textualize_status_output(names):
    s = OrderedDict()
    for name, zone_status, zone_warnings, zone_errors, delegation_status, delegation_warnings, delegation_errors, responses in names:
        s.update(_textualize_status_output_name(name, zone_status, zone_warnings, zone_errors, delegation_status, delegation_warnings, delegation_errors, responses))

    return s


def finish_graph(G: DNSAuthGraph, name_objs, rdtypes, trusted_keys, supported_algs, filename):
    G.add_trust(trusted_keys, supported_algs=supported_algs)

    tuples = []
    processed = set()
    for name_obj in name_objs:
        name_obj.populate_response_component_status(G)
        tuples.extend(name_obj.serialize_status_simple(rdtypes, processed))

    return textualize_status_output(tuples)


def check(analysis_structured):
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

    if latest_analysis_date is None:
        logger.error('The analysis of "%s" doesn\'t include at least one analysis.' % lb2s(name.to_text()))
        return None, None

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

    return G, finish_graph(G, name_objs, rdtypes, trusted_keys, supported_algs, None)
