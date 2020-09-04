#!/usr/bin/env python

import typing
import logging
import json
import socket
import sys
import threading
import re
import random
import binascii
import struct
import urllib.parse
from collections import OrderedDict

import dns.edns, dns.exception, dns.name, dns.rdataclass, dns.rdatatype, dns.rdtypes.ANY.NS, dns.rdtypes.IN.A, dns.rdtypes.IN.AAAA, dns.rrset
from dnsviz.analysis import (
    COOKIE_STANDIN,
    WILDCARD_EXPLICIT_DELEGATION,
    PrivateAnalyst,
    PrivateRecursiveAnalyst,
    OnlineDomainNameAnalysis,
    OfflineDomainNameAnalysis,
    NetworkConnectivityException,
    Analyst,
)
from dnsviz.format import humanize_name, latin1_binary_to_string as lb2s
from dnsviz.ipaddr import IPAddr
from dnsviz.query import DiagnosticQuery, QuickDNSSECQuery, StandardRecursiveQueryCD
from dnsviz.resolver import Resolver, PrivateFullResolver
from dnsviz import transport
from dnsviz.util import get_client_address, get_root_hints
from dnsviz.commands.probe import A_ROOT_IPV4, A_ROOT_IPV6
from dnsviz.transport import DNSQueryTransportHandlerFactory


logging.basicConfig(level=logging.WARNING, format="%(message)s")
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class CustomQueryMixin:
    edns_options = []


class ProbeConfig(typing.NamedTuple):
    client_ipv4: typing.Optional[IPAddr] = None
    client_ipv6: typing.Optional[IPAddr] = None
    try_ipv4: bool = True
    try_ipv6: bool = True
    query_authoritative_servers: bool = True
    server_list: typing.Optional[str] = []
    stop_at_explicit: typing.Dict[dns.name.Name, bool] = {}
    dlv_domain: typing.Optional[dns.name.Name] = None
    edns_diagnostics: bool = False
    cache_level: typing.Optional[int] = None
    explicit_only: bool = True
    meta_only: bool = False
    rdtypes: typing.List[dns.rdtypes.nsbase.NSBase] = []
    th_factories: typing.Optional[typing.Iterable[DNSQueryTransportHandlerFactory]] = None


def _get_dns_cookie_option(cookie=None):
    if cookie is None:
        r = random.getrandbits(64)
        cookie = struct.pack(b"Q", r)
    else:
        cookie = binascii.unhexlify(cookie)
    return dns.edns.GenericOption(10, cookie)


def _init_stub_resolver(tm, explicit_delegations, odd_ports):
    servers = set()
    for rdata in explicit_delegations[(WILDCARD_EXPLICIT_DELEGATION, dns.rdatatype.NS)]:
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            if (rdata.target, rdtype) in explicit_delegations:
                servers.update([IPAddr(r.address) for r in explicit_delegations[(rdata.target, rdtype)]])
    return Resolver(list(servers), StandardRecursiveQueryCD, transport_manager=tm)


def _init_full_resolver(tm, explicit_delegations, odd_ports):
    quick_query = QuickDNSSECQuery.add_mixin(CustomQueryMixin).add_server_cookie(COOKIE_STANDIN)
    diagnostic_query = DiagnosticQuery.add_mixin(CustomQueryMixin).add_server_cookie(COOKIE_STANDIN)

    # now that we have the hints, make resolver a full resolver instead of a stub
    hints = get_root_hints()
    for key in explicit_delegations:
        hints[key] = explicit_delegations[key]
    return PrivateFullResolver(
        hints,
        query_cls=(quick_query, diagnostic_query),
        odd_ports=odd_ports,
        cookie_standin=COOKIE_STANDIN,
        transport_manager=tm,
    )


def _add_servers(domain: dns.name.Name, addr_mappings: typing.List[typing.Union[str, typing.Tuple[str, int]]], delegation_mapping, odd_ports):
    for i, addr in enumerate(addr_mappings, 1):
        port = 53
        if isinstance(addr, tuple):
            addr, port = addr

        # Domain -> Name
        name = dns.name.from_text("ns%d" % i)
        delegation_mapping[(domain, dns.rdatatype.NS)].add(
            dns.rdtypes.ANY.NS.NS(dns.rdataclass.IN, dns.rdatatype.NS, name)
        )

        # Name -> IP 
        try:
            addr_ipaddr = IPAddr(addr)
        except ValueError as e:
            raise e

        if addr_ipaddr.version == 6:
            a_rdtype = dns.rdatatype.AAAA
            rdtype_cls = dns.rdtypes.IN.AAAA.AAAA
        else:
            a_rdtype = dns.rdatatype.A
            rdtype_cls = dns.rdtypes.IN.A.A

        if (name, a_rdtype) not in delegation_mapping:
            delegation_mapping[(name, a_rdtype)] = dns.rrset.RRset(name, dns.rdataclass.IN, a_rdtype)
        delegation_mapping[(name, a_rdtype)].add(rdtype_cls(dns.rdataclass.IN, a_rdtype, addr))
        if port != 53:
            odd_ports[(domain, addr_ipaddr)] = port


def _get_explicit_delegations(tm, server_list: typing.Optional[typing.List[typing.Union[str, typing.Tuple[str, int]]]]):
    explicit_delegations = {}
    odd_ports = {}
    explicit_delegations[(WILDCARD_EXPLICIT_DELEGATION, dns.rdatatype.NS)] = dns.rrset.RRset(
        WILDCARD_EXPLICIT_DELEGATION, dns.rdataclass.IN, dns.rdatatype.NS
    )
    if not server_list:
        bootstrap_resolver = Resolver.from_file("/etc/resolv.conf", StandardRecursiveQueryCD, transport_manager=tm)
        server_list = bootstrap_resolver._servers
    _add_servers(
        WILDCARD_EXPLICIT_DELEGATION, server_list, explicit_delegations, odd_ports,
    )
    return (explicit_delegations, odd_ports)


def _probe(
    analyst_cls: Analyst,
    name: str,
    config,
    rdclass,
    ceiling,
    query_class_mixin,
    explicit_delegations,
    odd_ports,
    cache,
    cache_lock,
    tm,
    resolver,
):
    if ceiling is not None and name.is_subdomain(ceiling):
        c = ceiling
    else:
        c = name
    try:
        a = analyst_cls(
            name,
            rdclass=rdclass,
            dlv_domain=config.dlv_domain,
            try_ipv4=config.try_ipv4,
            try_ipv6=config.try_ipv6,
            client_ipv4=config.client_ipv4,
            client_ipv6=config.client_ipv6,
            query_class_mixin=query_class_mixin,
            ceiling=c,
            edns_diagnostics=config.edns_diagnostics,
            explicit_delegations=explicit_delegations,
            stop_at_explicit=config.stop_at_explicit,
            odd_ports=odd_ports,
            extra_rdtypes=config.rdtypes,
            explicit_only=config.explicit_only,
            analysis_cache=cache,
            cache_level=config.cache_level,
            analysis_cache_lock=cache_lock,
            transport_manager=tm,
            th_factories=config.th_factories,
            resolver=resolver,
            logger=logger,
        )
        return a.analyze()
    # report exceptions related to network connectivity
    except (NetworkConnectivityException, transport.RemoteQueryTransportError) as e:
        logger.error("Error analyzing %s: %s" % (humanize_name(name), e))
    except:
        logger.exception("Error analyzing %s" % humanize_name(name))
    return None


def init():
    if get_client_address(A_ROOT_IPV4) is None:
        print("No global IPv4 connectivity detected")
    if get_client_address(A_ROOT_IPV6) is None:
        print("No global IPv6 connectivity detected")


def probe(config: ProbeConfig, name_list: typing.List[str], cache={}):
    tm = transport.DNSQueryTransportManager()
    try:
        rdclass = dns.rdataclass.IN
        ceiling = None
        analyst_cls = None
        new_resolver_function = None

        if config.query_authoritative_servers:
            explicit_delegations = {}
            odd_ports = {}
            ceiling = dns.name.root
            analyst_cls = PrivateAnalyst
            new_resolver_function = _init_full_resolver
        else:
            explicit_delegations, odd_ports = _get_explicit_delegations(
                tm, config.server_list
            )
            ceiling = None
            analyst_cls = PrivateRecursiveAnalyst
            new_resolver_function = _init_stub_resolver

        resolver = new_resolver_function(tm, explicit_delegations, odd_ports)

        query_class_mixin = CustomQueryMixin
        CustomQueryMixin.edns_options.append(_get_dns_cookie_option())

        cache_lock = threading.Lock()

        analysis_structured = OrderedDict()
        analysis_structured['_meta._dnsviz.'] = { 'names': [lb2s(n) for n in name_list] }
        for name in name_list:
            try:
                name = dns.name.from_text(name)
            except UnicodeDecodeError as e:
                logger.error('%s: "%s"' % (e, name))
            except dns.exception.DNSException:
                logger.error('The domain name was invalid: "%s"' % name)
            else:
                r = _probe(
                    analyst_cls,
                    name,
                    config,
                    rdclass,
                    ceiling,
                    query_class_mixin,
                    explicit_delegations,
                    odd_ports,
                    cache,
                    cache_lock,
                    tm,
                    resolver,
                )
                if r is not None:
                    r.serialize(analysis_structured, config.meta_only)

        return analysis_structured
    finally:
        tm.close()
