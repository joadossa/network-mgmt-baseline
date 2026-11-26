# -*- coding: utf-8 -*-
"""Filtros do projeto network-mgmt-baseline.

1. Engine de compliance genérica, orientada a catálogo (Cisco IOS/IOS-XE,
   NX-OS, Huawei VRP): avalia regras de regex contra a configuração/saídas
   coletadas e devolve resultados PASS/FAIL/ERROR/SKIPPED.
2. Helpers para montar os payloads enviados à API do FortiOS.

Usa apenas a biblioteca padrão do Python (sem netaddr), para rodar igual
no controlador, no AWX/EE e nos testes offline (tests/).
"""

from __future__ import absolute_import, division, print_function

import ipaddress
import json
import re

__metaclass__ = type

try:  # dentro do Ansible
    from ansible.errors import AnsibleFilterError
except ImportError:  # testes offline sem Ansible instalado
    class AnsibleFilterError(Exception):
        pass


SEVERITIES = ('info', 'low', 'medium', 'high', 'critical')
SEVERITY_RANK = dict((s, i) for i, s in enumerate(SEVERITIES))
CHECK_TYPES = ('present', 'absent', 'any_section', 'each_section', 'each_section_absent')
SECTION_TYPES = ('any_section', 'each_section', 'each_section_absent')
PLACEHOLDER_RE = re.compile(r'__([A-Z][A-Z0-9_]*?)__')
PAGING_RE = re.compile(r'-{2,}\s*More\s*-{2,}|--More--', re.IGNORECASE)
MAX_MATCHES = 5
NET_KEYS = ('cidr', 'network', 'prefix', 'ip', 'address', 'host', 'server')


# ---------------------------------------------------------------------------
# Utilidades gerais
# ---------------------------------------------------------------------------
def _to_bool(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ('true', 'yes', 'on', '1', 'sim', 'y'):
        return True
    if text in ('false', 'no', 'off', '0', 'nao', 'não', 'n', ''):
        return False
    return default


def _text(value):
    if value is None:
        return ''
    if isinstance(value, (list, tuple)):
        return '\n'.join(_text(v) for v in value)
    return str(value)


def _normalize(value):
    text = _text(value).replace('\r\n', '\n').replace('\r', '\n')
    return '\n'.join(line.rstrip() for line in text.split('\n'))


def _placeholder_key(key):
    return re.sub(r'[^A-Z0-9]+', '_', str(key).upper()).strip('_')


def _server_ip(server):
    if isinstance(server, dict):
        for key in ('ip', 'address', 'host', 'server'):
            if server.get(key) not in (None, ''):
                return str(server[key])
        return ''
    return str(server)


# ---------------------------------------------------------------------------
# Endereçamento (substitui ansible.utils/netaddr)
# ---------------------------------------------------------------------------
def _parse_net(value):
    text = str(value or '').strip()
    parts = text.replace('/', ' ').split()
    if not parts:
        raise ValueError('vazio')
    if len(parts) == 2:
        return ipaddress.ip_network(u'%s/%s' % (parts[0], parts[1]), strict=False)
    return ipaddress.ip_network(parts[0], strict=False)


def netbaseline_invalid_cidrs(values, version=None):
    """Itens que não são redes válidas (ou não são da versão IP pedida)."""
    bad = []
    for value in values or []:
        try:
            net = _parse_net(value)
            if version and net.version != int(version):
                bad.append(value)
        except (ValueError, TypeError):
            bad.append(value)
    return bad


def netbaseline_ip_in_networks(ip, networks):
    try:
        addr = ipaddress.ip_address(str(ip).split('/')[0].strip())
    except ValueError:
        return False
    for net in networks or []:
        try:
            if addr in _parse_net(net):
                return True
        except (ValueError, TypeError):
            continue
    return False


def netbaseline_server_ips(servers):
    return [_server_ip(s) for s in servers or [] if _server_ip(s)]


def netbaseline_name_list(values):
    return [{'name': str(v)} for v in values or []]


def _network_context(value):
    """Placeholders derivados de uma rede: valor cru (raw) e versão regex."""
    try:
        net = _parse_net(value)
    except (ValueError, TypeError):
        return {}, {}
    ip = str(net.network_address)
    mask = str(net.netmask)
    wildcard = str(net.hostmask)
    prefix = str(net.prefixlen)
    raw = {
        'IP': ip,
        'CIDR': '%s/%s' % (ip, prefix),
        'PREFIX': prefix,
        'MASK': mask,
        'WILDCARD': wildcard,
        'IPMASK': '%s %s' % (ip, mask),
    }
    rx = dict((k, re.escape(v)) for k, v in raw.items())
    e_ip = re.escape(ip)
    if net.prefixlen == net.max_prefixlen:
        # Cisco: "host X", "X" ou "X 0.0.0.0"   |  Huawei: "X 0", "X 0.0.0.0", "X 32", "X/32"
        raw['CISCO_SRC'] = 'host %s' % ip
        rx['CISCO_SRC'] = r'(?:host\s+%s|%s(?:\s+0\.0\.0\.0)?(?!\s+\d+\.\d+))' % (e_ip, e_ip)
        raw['HUAWEI_SRC'] = '%s 0' % ip
        rx['HUAWEI_SRC'] = r'%s(?:\s+(?:0|0\.0\.0\.0|%s)|/%s)' % (e_ip, prefix, prefix)
    else:
        raw['CISCO_SRC'] = '%s %s' % (ip, wildcard)
        rx['CISCO_SRC'] = r'%s\s+%s' % (e_ip, re.escape(wildcard))
        raw['HUAWEI_SRC'] = '%s %s' % (ip, wildcard)
        rx['HUAWEI_SRC'] = r'%s(?:\s+(?:%s|%s)|/%s)' % (e_ip, re.escape(wildcard), prefix, prefix)
    return raw, rx


def _item_context(item):
    raw = {}
    base = None
    if isinstance(item, dict):
        for key, val in item.items():
            if isinstance(val, (str, int, float)) and not isinstance(val, bool):
                raw[_placeholder_key(key)] = str(val)
        for key in NET_KEYS:
            if item.get(key) not in (None, ''):
                base = item[key]
                break
        if base is not None:
            label = str(base)
        else:
            label = str(item.get('name', json.dumps(item, sort_keys=True, default=str)))
        raw.setdefault('NAME', str(item.get('name', label)))
    else:
        base = item
        label = str(item)
        raw['NAME'] = label
    raw['ITEM'] = label
    raw['LABEL'] = label
    rx = dict((k, re.escape(v)) for k, v in raw.items())
    if base is not None:
        n_raw, n_rx = _network_context(base)
        raw.update(n_raw)
        rx.update(n_rx)
    return raw, rx, label


class _PlaceholderError(Exception):
    pass


def _substitute(template, mapping):
    if template is None:
        return None

    def repl(match):
        key = match.group(1)
        if key not in mapping:
            raise _PlaceholderError(key)
        return mapping[key]

    return PLACEHOLDER_RE.sub(repl, str(template))


# ---------------------------------------------------------------------------
# Engine de compliance
# ---------------------------------------------------------------------------
def _indent(line):
    return len(line) - len(line.lstrip(' \t'))


def _sections(text, start_rx):
    """Seção = linha que casa com start_rx + linhas seguintes mais indentadas.

    Funciona para IOS/NX-OS (filhos indentados, '!' na coluna 0) e para
    Huawei VRP (filhos indentados, '#' na coluna 0), inclusive aninhadas
    (ex.: 'aaa' -> ' domain default_admin' -> '  hwtacacs-server ISE').
    """
    lines = text.split('\n')
    found = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() and start_rx.search(line):
            base = _indent(line)
            block = [line]
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if not nxt.strip() or _indent(nxt) <= base:
                    break
                block.append(nxt)
                j += 1
            found.append('\n'.join(block))
            i = j
        else:
            i += 1
    return found


def _matching_lines(text, rx, limit=MAX_MATCHES):
    out = []
    for match in rx.finditer(text):
        start = text.rfind('\n', 0, match.start()) + 1
        end = text.find('\n', max(match.end(), match.start() + 1) - 1)
        if end == -1:
            end = len(text)
        line = ' '.join(text[start:end].split())
        if line and line not in out:
            out.append(line)
        if len(out) >= limit:
            break
    return out


def _header(section):
    return section.split('\n', 1)[0].strip()


def _flags(check):
    flags = re.MULTILINE
    raw = str(check.get('flags', '')).lower()
    if 'i' in raw or _to_bool(check.get('ignorecase', False), False):
        flags |= re.IGNORECASE
    return flags


def _get_output(outputs, source, default_source):
    if not isinstance(outputs, dict) or source not in outputs:
        return None, 'SKIPPED', u'Fonte "%s" não coletada (modo offline ou check de runtime desativado)' % source
    entry = outputs.get(source)
    if entry is None:
        return None, 'ERROR', u'Falha ao executar "%s"' % source
    if isinstance(entry, dict):
        if not _to_bool(entry.get('ok', True)):
            return None, 'ERROR', u'Falha ao executar "%s": %s' % (source, entry.get('msg') or 'erro desconhecido')
        entry = entry.get('stdout', '')
    text = _normalize(entry)
    if PAGING_RE.search(text):
        return None, 'ERROR', u'Paginação detectada na saída de "%s" (verifique screen-length / terminal length)' % source
    if source == default_source and not text.strip():
        return None, 'ERROR', u'Saída vazia para "%s"' % source
    return text, None, None


def _result(check, label, status, detail, title, remediation, source):
    check_id = str(check.get('id', 'CHECK'))
    severity = str(check.get('severity', 'medium')).lower()
    if severity not in SEVERITY_RANK:
        severity = 'medium'
    return {
        'id': check_id if label is None else '%s[%s]' % (check_id, label),
        'check': check_id,
        'item': label,
        'category': str(check.get('category', 'GERAL')),
        'severity': severity,
        'status': status,
        'title': title or check_id,
        'detail': detail,
        'remediation': remediation or '',
        'source': source,
    }


def _evaluate_one(check, ctx_raw, ctx_rx, label, outputs, default_source):
    ctype = str(check.get('type', 'present')).strip()
    source = str(check.get('source') or default_source)
    try:
        title = _substitute(check.get('title') or check.get('id'), ctx_raw)
        remediation = _substitute(check.get('remediation', ''), ctx_raw)
    except _PlaceholderError as exc:
        return _result(check, label, 'ERROR', u'Placeholder __%s__ sem valor (use "items")' % exc,
                       str(check.get('title', '')), '', source)

    if ctype not in CHECK_TYPES:
        return _result(check, label, 'ERROR', u'Tipo de check inválido: %s' % ctype, title, remediation, source)

    text, status, detail = _get_output(outputs, source, default_source)
    if status:
        return _result(check, label, status, detail, title, remediation, source)

    flags = _flags(check)
    try:
        if 'pattern' not in check:
            raise KeyError('pattern')
        rx = re.compile(_substitute(check['pattern'], ctx_rx), flags)
        sec_rx = None
        if ctype in SECTION_TYPES:
            if 'section' not in check:
                raise KeyError('section')
            sec_rx = re.compile(_substitute(check['section'], ctx_rx), flags)
    except _PlaceholderError as exc:
        return _result(check, label, 'ERROR', u'Placeholder __%s__ sem valor (use "items")' % exc,
                       title, remediation, source)
    except KeyError as exc:
        return _result(check, label, 'ERROR', u'Campo obrigatório ausente no check: %s' % exc,
                       title, remediation, source)
    except re.error as exc:
        return _result(check, label, 'ERROR', u'Regex inválido: %s' % exc, title, remediation, source)

    if ctype == 'present':
        lines = _matching_lines(text, rx)
        if lines:
            return _result(check, label, 'PASS', u'Encontrado: ' + ' | '.join(lines), title, remediation, source)
        return _result(check, label, 'FAIL', u'Configuração esperada não encontrada', title, remediation, source)

    if ctype == 'absent':
        lines = _matching_lines(text, rx)
        if lines:
            return _result(check, label, 'FAIL', u'Encontrado (não permitido): ' + ' | '.join(lines),
                           title, remediation, source)
        return _result(check, label, 'PASS', u'Nenhuma ocorrência não permitida', title, remediation, source)

    sections = _sections(text, sec_rx)
    if not sections:
        if ctype == 'each_section_absent' and not _to_bool(check.get('require_section', False), False):
            return _result(check, label, 'PASS', u'Nenhuma seção correspondente (nada a violar)',
                           title, remediation, source)
        return _result(check, label, 'FAIL', u'Seção esperada não encontrada (regex: %s)' % sec_rx.pattern,
                       title, remediation, source)

    if ctype == 'any_section':
        for section in sections:
            lines = _matching_lines(section, rx, 2)
            if lines:
                return _result(check, label, 'PASS',
                               u'Encontrado em "%s": %s' % (_header(section), ' | '.join(lines)),
                               title, remediation, source)
        return _result(check, label, 'FAIL',
                       u'Nenhuma seção contém o esperado. Seções avaliadas: %s'
                       % ', '.join(_header(s) for s in sections[:MAX_MATCHES]),
                       title, remediation, source)

    if ctype == 'each_section':
        bad = [s for s in sections if not rx.search(s)]
        if bad:
            return _result(check, label, 'FAIL',
                           u'%d de %d seção(ões) fora do padrão: %s'
                           % (len(bad), len(sections), ', '.join(_header(s) for s in bad[:MAX_MATCHES])),
                           title, remediation, source)
        return _result(check, label, 'PASS',
                       u'%d seção(ões) conforme(s): %s'
                       % (len(sections), ', '.join(_header(s) for s in sections[:MAX_MATCHES])),
                       title, remediation, source)

    # each_section_absent
    bad = []
    for section in sections:
        lines = _matching_lines(section, rx, 1)
        if lines:
            bad.append(u'%s -> %s' % (_header(section), lines[0]))
    if bad:
        return _result(check, label, 'FAIL', u'Não permitido em: ' + ' | '.join(bad[:MAX_MATCHES]),
                       title, remediation, source)
    return _result(check, label, 'PASS', u'%d seção(ões) sem ocorrências não permitidas' % len(sections),
                   title, remediation, source)


def netbaseline_evaluate(outputs, checks, default_source='show running-config'):
    """Avalia o catálogo de checks contra as saídas coletadas.

    outputs: {comando: {'ok': bool, 'stdout': str, 'msg': str}} (ou {comando: str})
    checks : lista de dicts (ver roles/network_sanity_check/vars/*.yml)
    """
    results = []
    for check in checks or []:
        if not isinstance(check, dict) or not _to_bool(check.get('enabled', True)):
            continue
        items = check.get('items')
        if items is None:
            results.append(_evaluate_one(check, {}, {}, None, outputs, default_source))
            continue
        if isinstance(items, (str, dict)):
            items = [items]
        items = list(items)
        if not items:
            results.append(_result(check, None, 'ERROR', u'Lista "items" vazia — verifique as variáveis do inventário',
                                   str(check.get('title', check.get('id'))), '',
                                   str(check.get('source') or default_source)))
            continue
        for item in items:
            ctx_raw, ctx_rx, label = _item_context(item)
            results.append(_evaluate_one(check, ctx_raw, ctx_rx, label, outputs, default_source))
    return results


def netbaseline_sources(checks, default_source):
    """Comandos necessários para os checks habilitados (sem repetição)."""
    out = [str(default_source)]
    for check in checks or []:
        if isinstance(check, dict) and _to_bool(check.get('enabled', True)):
            source = str(check.get('source') or default_source)
            if source not in out:
                out.append(source)
    return out


def netbaseline_collect_outputs(results):
    """Converte o 'register' de um loop de cli_command em {comando: saída}."""
    out = {}
    for res in results or []:
        if not isinstance(res, dict) or res.get('item') is None or res.get('skipped'):
            continue
        failed = bool(res.get('failed')) or bool(res.get('unreachable'))
        out[str(res['item'])] = {
            'ok': not failed,
            'stdout': '' if failed else _text(res.get('stdout', '')),
            'msg': str(res.get('msg', '')) if failed else '',
        }
    return out


def netbaseline_host_digest(results):
    lines = []
    for res in results or []:
        if res.get('status') in ('FAIL', 'ERROR'):
            lines.append(u'[%s][%s] %s - %s: %s' % (res['status'], res['severity'], res['id'], res['title'], res['detail']))
    if not lines:
        total = len([r for r in results or [] if r.get('status') == 'PASS'])
        lines.append(u'Todos os checks avaliados estão conformes (%d PASS)' % total)
    return lines


# ---------------------------------------------------------------------------
# FortiOS — payloads
# ---------------------------------------------------------------------------
def fortios_ipmask(value):
    net = _parse_net(value)
    return '%s %s' % (net.network_address, net.netmask)


def fortios_addr_name(value, prefix='MGMT_'):
    net = _parse_net(value)
    return ('%s%s_%s' % (prefix, net.network_address, net.prefixlen))[:79]


def fortios_trusthosts(networks, fill=True, maximum=10):
    nets = [fortios_ipmask(n) for n in networks or []]
    if len(nets) > int(maximum):
        raise AnsibleFilterError('FortiOS aceita no máximo %s trusthosts por admin (recebido %d)' % (maximum, len(nets)))
    out = {}
    for idx in range(1, int(maximum) + 1):
        if idx <= len(nets):
            out['trusthost%d' % idx] = nets[idx - 1]
        elif _to_bool(fill):
            out['trusthost%d' % idx] = '0.0.0.0 0.0.0.0'   # slot sem uso
    return out


def fortios_tacacs_payload(servers, key, opts=None):
    opts = opts or {}
    servers = list(servers or [])[:3]
    payload = {
        'name': str(opts.get('name', 'TACACS')),
        'port': int(opts.get('port') or 49),
        'authen_type': str(opts.get('authen_type') or 'auto'),
        'authorization': str(opts.get('authorization') or 'enable'),
    }
    slots = (('server', 'key'), ('secondary_server', 'secondary_key'), ('tertiary_server', 'tertiary_key'))
    for (srv_field, key_field), srv in zip(slots, servers):
        payload[srv_field] = _server_ip(srv)
        own_key = srv.get('key') if isinstance(srv, dict) else None
        payload[key_field] = str(own_key or key)
    for opt in ('source_ip', 'interface', 'interface_select_method'):
        if opts.get(opt) not in (None, ''):
            payload[opt] = str(opts[opt])
    if opts.get('interface') and not opts.get('interface_select_method'):
        payload['interface_select_method'] = 'specify'
    return payload


def fortios_tacacs_acct_payload(servers, key, opts=None):
    opts = opts or {}
    servers = list(servers or [])
    if not servers:
        return {'status': 'disable'}
    first = servers[0]
    own_key = first.get('key') if isinstance(first, dict) else None
    payload = {'status': 'enable', 'server': _server_ip(first), 'server_key': str(own_key or key)}
    if opts.get('source_ip') not in (None, ''):
        payload['source_ip'] = str(opts['source_ip'])
    if opts.get('interface') not in (None, ''):
        payload['interface'] = str(opts['interface'])
        payload['interface_select_method'] = 'specify'
    return payload


def fortios_syslog_payload(servers, slot, opts=None):
    opts = opts or {}
    servers = list(servers or [])
    idx = int(slot) - 1
    if idx >= len(servers):
        return {'status': 'disable'}
    srv = servers[idx]
    get = srv.get if isinstance(srv, dict) else (lambda k, d=None: d)
    payload = {
        'status': 'enable',
        'server': _server_ip(srv),
        'port': int(get('port') or opts.get('port') or 514),
        'mode': str(get('mode') or opts.get('mode') or 'udp'),
        'facility': str(get('facility') or opts.get('facility') or 'local7'),
    }
    if opts.get('format') not in (None, ''):
        payload['format'] = str(opts['format'])
    if opts.get('source_ip') not in (None, ''):
        payload['source_ip'] = str(opts['source_ip'])
    if opts.get('interface') not in (None, ''):
        payload['interface'] = str(opts['interface'])
        payload['interface_select_method'] = 'specify'
    return payload


def fortios_localin_policies(interfaces, opts=None):
    """Par de local-in policies por interface: accept (redes de gerência) + deny (resto)."""
    opts = opts or {}
    base = int(opts.get('policyid_base') or 900)
    services = [str(s) for s in (opts.get('services') or ['HTTPS', 'SSH', 'PING'])]
    group = str(opts.get('addrgrp') or 'GRP-MGMT-ACCESS')
    intf_format = str(opts.get('intf_format') or 'string')
    out = []
    for idx, intf in enumerate(interfaces or []):
        for offset, action, src, comment in (
                (0, 'accept', group, 'Ansible: permite gerencia a partir de %s' % group),
                (1, 'deny', 'all', 'Ansible: bloqueia gerencia de origens nao autorizadas')):
            policy = {
                'policyid': base + idx * 2 + offset,
                'action': action,
                'srcaddr': [{'name': src}],
                'dstaddr': [{'name': 'all'}],
                'service': [{'name': s} for s in services],
                'schedule': 'always',
                'status': 'enable',
                'comments': comment,
            }
            if intf_format == 'list':
                policy['intf_dict'] = [{'name': str(intf)}]
            else:
                policy['intf'] = str(intf)
            out.append(policy)
    return out


class FilterModule(object):
    """Filtros do baseline de gerência (sanity check + payloads FortiOS)."""

    def filters(self):
        return {
            # engine
            'netbaseline_evaluate': netbaseline_evaluate,
            'netbaseline_sources': netbaseline_sources,
            'netbaseline_collect_outputs': netbaseline_collect_outputs,
            'netbaseline_host_digest': netbaseline_host_digest,
            # endereçamento
            'netbaseline_invalid_cidrs': netbaseline_invalid_cidrs,
            'netbaseline_ip_in_networks': netbaseline_ip_in_networks,
            'netbaseline_server_ips': netbaseline_server_ips,
            'netbaseline_name_list': netbaseline_name_list,
            # FortiOS
            'fortios_ipmask': fortios_ipmask,
            'fortios_addr_name': fortios_addr_name,
            'fortios_trusthosts': fortios_trusthosts,
            'fortios_tacacs_payload': fortios_tacacs_payload,
            'fortios_tacacs_acct_payload': fortios_tacacs_acct_payload,
            'fortios_syslog_payload': fortios_syslog_payload,
            'fortios_localin_policies': fortios_localin_policies,
        }
