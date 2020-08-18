import typing


class GrokConfig(typing.NamedTuple):
    trusted_keys: typing.List = []
    strict_cookies: bool = False
    allow_private: bool = False
    supported_algs: typing.Optional[typing.List] = None
    supported_digest_algs: typing.Optional[typing.List] = None


def grok(config: GrokConfig, probe_result):
    cache = {}

    grok_result = OrderedDict()
    for name in probe_result:
        name = dns.name.from_text(name)
        name_obj = OfflineDomainNameAnalysis.deserialize(
            name, probe_result, cache, strict_cookies=config.strict_cookies, allow_private=config.allow_private,
        )
        name_obj.populate_status(
            config.trusted_keys,
            supported_algs=config.supported_algs,
            supported_digest_algs=config.supported_digest_algs,
        )
        name_obj.serialize_status(grok_result, loglevel=logging.INFO)
    return grok_result