import logging
import json

import httpx
import searxinstances.model
from urllib.parse import urlparse
from . import dnssec, simple


logging.basicConfig(level=logging.WARNING, format="%(levelname)s:%(message)s")
logger = logging.getLogger()


def initialize_logging():
    logging.basicConfig(level=logging.DEBUG)
    for logger_name in ('httpx', 'httpx.client', 'httpx.config', 'hpack.hpack', 'hpack.table',
                        'httpx.dispatch.connection_pool', 'httpx.dispatch.connection',
                        'httpx.dispatch.http2', 'httpx.dispatch.http11',
                        'ipwhois.rdap', 'ipwhois.ipwhois', 'ipwhois.net', 'ipwhois.asn',
                        'urllib3.connectionpool', 'dnspython', 'dnsviz.analysis.online', 'dnsviz.analysis.offline',
                        'dnssec'):
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def get_record(check_result, hostname, record_name, hosts=set()):
    result = list()
    if hostname in hosts:
        return result

    hosts.add(hostname)

    value = check_result.get(hostname, {}).get(record_name, {})
    rdata = value.get('<rdata>', {})
    for item in list(rdata.keys()):
        if item.startswith('CNAME '):
            result = result + get_record(check_result, item[6:-1], record_name, hosts)
        else:
            result.append(item)
    return result


def process_hostname(hostname: str, probe_config):
    result = dnssec.analyze(hostname, probe_config)
    if result:
        # status
        status = dnssec.get_status(result)
        print(" ", hostname, "status=", status)

        # additional informations
        last_key = list(result.keys())[-1]
        a_record = get_record(result, last_key, 'A')
        aaaa_record = get_record(result, last_key, 'AAAA')
        print(" ", hostname, "->", last_key)
        print(" ", hostname, "A=", a_record)
        print(" ", hostname, "AAAA=", aaaa_record)
    else:
        print(" ", hostname, "Error")


def check_simple(hostname: str):
    result = simple.get_info(hostname)
    print(" ", hostname, result)


if __name__ == "__main__":
    initialize_logging()
    cache = {}
    instances = searxinstances.model.load()
    dnssec.init()
    probe_config = dnssec.get_config()
    with httpx.Client(http2=True) as client:
        i = 1
        for instance in instances.keys():
            hostname = None
            try:
                response = client.get(instance)
                response.raise_for_status()
                url = str(response.url)
                hostname = urlparse(url).hostname
            except Exception as e:
                # logger.error("%s Error: %s", str(instance), str(e))
                pass
            else:
                if hostname not in ['search.jigsaw-security.com']:
                    print(i, instance)
                    check_simple(hostname)
                    process_hostname(hostname, probe_config)
                    i += 1
