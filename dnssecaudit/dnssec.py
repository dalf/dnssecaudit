import logging
import json
import multiprocessing
import ctypes
import dns.rdatatype
from . import probe, check, simple


logger = logging.getLogger(__name__)


def _inprocess_analyze(retval: multiprocessing.Array, done: multiprocessing.Value, hostname: str, probe_config, output_path: str=None, output_format: str=None):
    logger.debug("probe: %s", hostname)
    analysis_structured = probe.probe(probe_config, [hostname], cache={})
    logger.debug("check: %s", hostname)
    graph, check_result = check.check(analysis_structured)
    if check_result is not None and graph is not None:
        if output_path:
            graph.draw(format=output_format, path=output_path)
    retval.value = json.dumps(check_result).encode()
    done.value = True


def analyze(hostname: str, probe_config: probe.ProbeConfig, output_path: str=None, output_format: str=None):
    # horrible workaround for https://github.com/dalf/dnssecaudit/issues/1
    # start a new process to avoid all side effects related to dnsviz
    result = multiprocessing.Array(ctypes.c_char, 1024 * 100)
    done = multiprocessing.Value(ctypes.c_bool, False)
    p = multiprocessing.Process(target=_inprocess_analyze, args=(result, done, hostname, probe_config, output_path, output_format))
    p.start()
    p.join()
    if done.value > 0:
        return json.loads(result.value.decode())
    else:
        return None


def get_status(analyze_result):
    status = set()

    def add_status(key, obj, name):
        status.add(obj.get('<status>', 'UNKNOWN'))
        if '<status>' not in obj or obj['<status>'] != 'SECURE':
            return False
        return True

    for key, values in analyze_result.items():
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

    if len(status) > 1 and 'SECURE' in status:
        status.remove('SECURE')
    return status


def get_config() -> probe.ProbeConfig:
    rdtypes = [dns.rdatatype.from_text(x) for x in ['A', 'AAAA']]
    return probe.ProbeConfig(rdtypes=rdtypes)


def init():
    probe.init()
