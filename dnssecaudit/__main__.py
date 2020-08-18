import logging
import json
import dns.rdatatype

import httpx
from . import probe, check, simple
import searxinstances.model
from urllib.parse import urlparse


logging.basicConfig(level=logging.WARNING, format="%(levelname)s:%(message)s")
logger = logging.getLogger()


def initialize_logging():
    logging.basicConfig(level=logging.DEBUG)
    for logger_name in ('httpx', 'httpx.client', 'httpx.config', 'hpack.hpack', 'hpack.table',
                        'httpx.dispatch.connection_pool', 'httpx.dispatch.connection',
                        'httpx.dispatch.http2', 'httpx.dispatch.http11',
                        'ipwhois.rdap', 'ipwhois.ipwhois', 'ipwhois.net', 'ipwhois.asn',
                        'urllib3.connectionpool', 'dnsviz.analysis.online', 'dnsviz.analysis.offline'):
        logging.getLogger(logger_name).setLevel(logging.WARNING)
    for logginer_name in ('dnsviz.analysis.online', 'dnsviz.analysis.offline', 'dnspython'):
        logging.getLogger(logger_name).setLevel(logging.DEBUG)


def get_record(check_result, host, record_name, hosts=set()):
    result = list()
    if host in hosts:
        return result

    hosts.add(host)

    value = check_result.get(host, {}).get(record_name, {})
    rdata = value.get('<rdata>', {})

    for item in list(rdata.keys()):
        if item.startswith('CNAME '):
            result = result + get_record(check_result, item[6:-1], record_name, hosts)
        else:
            result.append(item)
    return result


def is_secure(check_result):
    status = set()

    def add_status(key, obj, name):
        status.add(obj.get('<status>', 'UNKNOWN'))
        if '<status>' not in obj or obj['<status>'] != 'SECURE':
            return False
        return True

    for key, values in check_result.items():
        if '<delegation>' in values:
            delegation = values['<delegation>']
            add_status(key, delegation, 'deletegation')
        if '<zone>' in values:
            zone = values['<zone>']
            if not add_status(key, zone, "zone"):
                for rdtype_key, rdtype_value in zone.get('<rdtype>', {}):
                    add_status(key, rdtype_value, rdtype_key)
                for rdata_key, rdata_value in zone.get('<rdata>', {}):
                    add_status(key, rdata_value, rdata_key)
    return status


def check_dnssec(host: str, probe_config, cache):
    print(" ", host, "probe")
    analysis_structured = probe.probe(probe_config, [host], cache=cache)
    print(" ", host, "check")
    graph, check_result = check.check(analysis_structured)
    if check_result is not None and graph is not None:
        last_key = list(check_result.keys())[-1]
        status = is_secure(check_result)
        a_record = get_record(check_result, last_key, 'A')
        aaaa_record = get_record(check_result, last_key, 'AAAA')
        print(" ", host, "->", last_key)
        print(" ", host, "status=", status)
        print(" ", host, "A=", a_record)
        print(" ", host, "AAAA=", aaaa_record)
        output_filename='{0}.jpg'.format(host)
        graph.draw(format='jpg', path=output_filename)


def check_simple(host: str):
    result = simple.get_info(host)
    print(" ", host, result)


def prune_cache(cache):
    return { key: value for key, value in cache.items() if str(key).count('.') <= 1 }


if __name__ == "__main__":
    initialize_logging()
    cache = {}
    rdtypes = [dns.rdatatype.from_text(x) for x in ['A', 'AAAA']]
    instances = searxinstances.model.load()
    probe_config = probe.ProbeConfig(rdtypes=rdtypes)
    probe.init()
    with httpx.Client(http2=True) as client:
        for instance in instances:
            available = False
            try:
                response = client.get(instance)
                response.raise_for_status()
                print("%s, %i", instance, response.status_code)
            except Exception as e:
                logger.exception("Error: %s", instance, e)
            finally:
                parsed_url = urlparse(str(response.url))
                check_simple(parsed_url.hostname)
                check_dnssec(parsed_url.hostname, probe_config, cache)
                cache = prune_cache(cache)
