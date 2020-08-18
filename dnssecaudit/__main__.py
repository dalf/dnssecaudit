import dns.rdatatype

import httpx
from . import probe, check
import searxinstances.model
from urllib.parse import urlparse


def check_dnssec(host: str, cache):
    check.print_result(probe.probe(probe.ProbeConfig(server_list=["tcp:1.1.1.1"], rdtypes=rdtypes), [host], cache=cache))

if __name__ == "__main__":
    cache = {}
    rdtypes = [dns.rdatatype.from_text(x) for x in ['A', 'AAAA']]
    instances = searxinstances.model.load()
    probe.init()
    with httpx.Client(http2=True) as client:
        for instance in instances:
            available = False
            try:
                response = client.get(instance)
                if response.status_code == 200:
                    available = True
            except:
                pass
            finally:
                if available:
                    parsed_url = urlparse(instance)
                    check_dnssec(parsed_url.hostname, cache)
