# -*- coding: utf-8 -*-
"""Filtros do projeto network-mgmt-baseline.

1. Engine de compliance genérica, orientada a catálogo (Cisco IOS/IOS-XE,
   NX-OS, Huawei VRP): avalia regras de regex contra a configuração/saídas
   coletadas e devolve resultados PASS/FAIL/ERROR/SKIPPED.
2. Helpers para montar os payloads FortiOS e verificar o baseline aplicado.

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


def netbaseline_blocking(results, min_severity='high'):
    """Resultados FAIL/ERROR com severidade >= min_severity (para falhar o job)."""
    threshold = SEVERITY_RANK.get(str(min_severity).lower(), SEVERITY_RANK['high'])
    return [r for r in results or []
            if r.get('status') in ('FAIL', 'ERROR') and SEVERITY_RANK.get(r.get('severity'), 2) >= threshold]


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


# ---------------------------------------------------------------------------
# FortiOS — leitura e verificação
# ---------------------------------------------------------------------------
def fortios_collect_facts(results):
    """register de loop de fortios_configuration_fact -> {seletor: results}."""
    facts = {}
    for res in results or []:
        if not isinstance(res, dict):
            continue
        selector = res.get('item')
        if isinstance(selector, dict):
            selector = selector.get('selector')
        selector = str(selector)
        if res.get('failed') or res.get('unreachable'):
            facts[selector] = {'__error__': str(res.get('msg') or 'falha na consulta à API')}
            continue
        meta = res.get('meta')
        if isinstance(meta, list):
            meta = meta[0] if meta else {}
        if not isinstance(meta, dict):
            facts[selector] = {'__error__': 'resposta da API sem campo "meta"'}
            continue
        if 'results' not in meta and meta.get('status') not in (None, 'success'):
            facts[selector] = {'__error__': 'API retornou %s (HTTP %s)' % (meta.get('status'), meta.get('http_status'))}
            continue
        facts[selector] = meta.get('results', [])
    return facts


def fortios_fact_errors(facts):
    """Seletores cuja leitura falhou: {seletor: mensagem}."""
    return dict((k, v['__error__']) for k, v in (facts or {}).items()
                if isinstance(v, dict) and '__error__' in v)


def _fgt_table(facts, selector):
    value = (facts or {}).get(selector)
    if value is None:
        return None, u'Seletor "%s" não coletado' % selector
    if isinstance(value, dict) and '__error__' in value:
        return None, u'Erro ao ler "%s": %s' % (selector, value['__error__'])
    if isinstance(value, dict):
        return [value], None
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)], None
    return None, u'Formato inesperado em "%s"' % selector


def _fgt_single(facts, selector):
    rows, err = _fgt_table(facts, selector)
    if err:
        return None, err
    return (rows[0] if rows else {}), None


def _fgt_get(obj, field):
    for key in (field, field.replace('_', '-'), field.replace('-', '_')):
        if key in (obj or {}):
            return obj[key]
    return None


def _fgt_find(rows, key, value):
    for row in rows or []:
        if str(_fgt_get(row, key)) == str(value):
            return row
    return None


def _fgt_names(value):
    if value in (None, ''):
        return []
    if isinstance(value, dict):
        return [str(value['name'])] if value.get('name') not in (None, '') else []
    if isinstance(value, (list, tuple)):
        out = []
        for val in value:
            out.extend(_fgt_names(val))
        return out
    return [v.strip('"') for v in str(value).split() if v.strip('"')]


def fortios_table_names(facts, selector):
    rows, err = _fgt_table(facts, selector)
    return [] if err else [str(_fgt_get(r, 'name')) for r in rows if _fgt_get(r, 'name') is not None]


def _norm_net(value):
    try:
        return str(_parse_net(value))
    except (ValueError, TypeError):
        return str(value or '').strip()


def _fgt_trusthosts(admin):
    nets = set()
    for idx in range(1, 11):
        val = _fgt_get(admin, 'trusthost%d' % idx)
        norm = _norm_net(val) if val else ''
        if norm and norm != '0.0.0.0/0':
            nets.add(norm)
    return nets


def fortios_baseline_evaluate(facts, expected):
    """Compara o estado lido via API com o baseline esperado (mesmo formato de resultado do sanity check)."""
    exp = expected or {}
    out = []

    def add(cid, cat, sev, title, status, detail, remediation='', item=None):
        out.append({
            'id': cid if item is None else '%s[%s]' % (cid, item),
            'check': cid, 'item': item, 'category': cat, 'severity': sev, 'status': status,
            'title': title, 'detail': detail, 'remediation': remediation, 'source': 'FortiOS API',
        })

    def judge(cid, cat, sev, title, problems, ok_detail, remediation='', item=None):
        if problems:
            add(cid, cat, sev, title, 'FAIL', '; '.join(problems), remediation, item)
        else:
            add(cid, cat, sev, title, 'PASS', ok_detail, remediation, item)

    def diff(obj, field, want, problems, label=None):
        have = _fgt_get(obj, field)
        if str(have) != str(want):
            problems.append(u'%s: esperado "%s", encontrado "%s"' % (label or field, want, have))

    tac = exp.get('tacacs') or {}
    acl = exp.get('acl') or {}
    admin_obj = None

    # ---------------- TACACS+ ----------------
    if _to_bool(tac.get('enabled', False), False):
        name = str(tac.get('name'))
        want_servers = netbaseline_server_ips(tac.get('servers'))[:3]
        rem = u'ansible-playbook fortinet_baseline.yml --tags tacacs (config user tacacs+ / edit %s)' % name
        rows, err = _fgt_table(facts, 'user_tacacs+')
        obj = _fgt_find(rows, 'name', name) if not err else None
        if err:
            add('FGT-TAC-001', 'TACACS', 'critical', u'Servidor TACACS+ "%s" configurado' % name, 'ERROR', err)
        elif not obj:
            add('FGT-TAC-001', 'TACACS', 'critical', u'Servidor TACACS+ "%s" configurado' % name, 'FAIL',
                u'Objeto "user tacacs+ %s" não encontrado' % name, rem)
        else:
            add('FGT-TAC-001', 'TACACS', 'critical', u'Servidor TACACS+ "%s" configurado' % name, 'PASS',
                u'Objeto encontrado')
            have = [str(v) for v in (_fgt_get(obj, 'server'), _fgt_get(obj, 'secondary-server'),
                                     _fgt_get(obj, 'tertiary-server')) if v not in (None, '')]
            judge('FGT-TAC-002', 'TACACS', 'critical', u'Servidores TACACS+ (primário/secundário/terciário)',
                  [] if have == want_servers else [u'esperado %s, encontrado %s' % (want_servers, have)],
                  u'Servidores: %s' % ', '.join(have), rem)
            problems = []
            diff(obj, 'authorization', tac.get('authorization', 'enable'), problems)
            have_port = _fgt_get(obj, 'port')
            want_port = int(tac.get('port') or 49)
            try:
                effective_port = int(have_port or 0) or 49   # 0 = padrão (49)
            except (TypeError, ValueError):
                effective_port = have_port
            if effective_port != want_port:
                problems.append(u'port: esperado %s, encontrado %s' % (want_port, have_port))
            judge('FGT-TAC-003', 'TACACS', 'high', u'Autorização TACACS+ e porta', problems,
                  u'authorization=%s port=%s' % (_fgt_get(obj, 'authorization'), have_port), rem)

        group = str(tac.get('group'))
        rows, err = _fgt_table(facts, 'user_group')
        if err:
            add('FGT-TAC-004', 'TACACS', 'critical', u'Grupo "%s" com membro "%s"' % (group, name), 'ERROR', err)
        else:
            grp = _fgt_find(rows, 'name', group)
            judge('FGT-TAC-004', 'TACACS', 'critical', u'Grupo "%s" com membro "%s"' % (group, name),
                  [u'grupo não encontrado'] if not grp else (
                      [] if name in _fgt_names(_fgt_get(grp, 'member')) else
                      [u'membro ausente (membros: %s)' % _fgt_names(_fgt_get(grp, 'member'))]),
                  u'Grupo encontrado com o servidor TACACS+ como membro', rem)

        admin = str(tac.get('admin'))
        rows, err = _fgt_table(facts, 'system_admin')
        if err:
            add('FGT-TAC-005', 'TACACS', 'critical', u'Administrador remoto "%s" (wildcard)' % admin, 'ERROR', err)
        else:
            admin_obj = _fgt_find(rows, 'name', admin)
            problems = []
            if not admin_obj:
                problems.append(u'administrador não encontrado')
            else:
                diff(admin_obj, 'remote-auth', 'enable', problems)
                diff(admin_obj, 'wildcard', 'enable', problems)
                diff(admin_obj, 'remote-group', group, problems)
                diff(admin_obj, 'accprofile', tac.get('accprofile'), problems)
            judge('FGT-TAC-005', 'TACACS', 'critical', u'Administrador remoto "%s" (wildcard)' % admin, problems,
                  u'remote-auth/wildcard ativos, grupo %s, perfil %s' % (group, tac.get('accprofile')), rem)

        if _to_bool(tac.get('accounting', False), False):
            obj, err = _fgt_single(facts, 'log.tacacs+accounting_setting')
            title = u'Accounting TACACS+ de comandos administrativos'
            if err:
                add('FGT-TAC-006', 'TACACS', 'medium', title, 'ERROR', err)
            else:
                problems = []
                diff(obj, 'status', 'enable', problems)
                if want_servers:
                    diff(obj, 'server', want_servers[0], problems)
                judge('FGT-TAC-006', 'TACACS', 'medium', title, problems,
                      u'Ativo para %s' % _fgt_get(obj, 'server'), rem)

    # ---------------- Syslog ----------------
    sl = exp.get('syslog') or {}
    if _to_bool(sl.get('enabled', False), False):
        servers = list(sl.get('servers') or [])
        opts = sl.get('opts') or {}
        rem = u'ansible-playbook fortinet_baseline.yml --tags syslog'
        for slot in range(1, 5):
            suffix = '' if slot == 1 else str(slot)
            sel = 'log.syslogd%s_setting' % suffix
            if slot <= len(servers):
                want = fortios_syslog_payload(servers, slot, opts)
                title = u'Syslog %d -> %s:%s (%s, %s)' % (slot, want['server'], want['port'], want['mode'], want['facility'])
                obj, err = _fgt_single(facts, sel)
                if err:
                    add('FGT-LOG-00%d' % slot, 'SYSLOG', 'high', title, 'ERROR', err)
                else:
                    problems = []
                    for field in ('status', 'server', 'port', 'mode', 'facility'):
                        diff(obj, field, want[field], problems)
                    judge('FGT-LOG-00%d' % slot, 'SYSLOG', 'high', title, problems, u'Configuração conforme', rem)
                fobj, err = _fgt_single(facts, 'log.syslogd%s_filter' % suffix)
                ftitle = u'Syslog %d: severidade mínima "%s"' % (slot, sl.get('severity'))
                if err:
                    add('FGT-LOG-10%d' % slot, 'SYSLOG', 'medium', ftitle, 'ERROR', err)
                else:
                    problems = []
                    diff(fobj, 'severity', sl.get('severity'), problems)
                    judge('FGT-LOG-10%d' % slot, 'SYSLOG', 'medium', ftitle, problems, u'Filtro conforme', rem)
            elif _to_bool(sl.get('disable_unused', True)):
                obj, err = _fgt_single(facts, sel)
                title = u'Syslog %d (slot sem uso) desativado' % slot
                if err:
                    add('FGT-LOG-00%d' % slot, 'SYSLOG', 'low', title, 'ERROR', err)
                else:
                    problems = []
                    diff(obj, 'status', 'disable', problems)
                    judge('FGT-LOG-00%d' % slot, 'SYSLOG', 'low', title, problems, u'Desativado', rem)

    # ---------------- ACL de gerência ----------------
    if _to_bool(acl.get('enabled', False), False):
        networks = list(acl.get('networks') or [])
        prefix = str(acl.get('addr_prefix', 'MGMT_'))
        rem = u'ansible-playbook fortinet_baseline.yml --tags acl'
        rows, err = _fgt_table(facts, 'firewall_address')
        for net in networks:
            name = fortios_addr_name(net, prefix)
            title = u'Objeto de endereço %s' % name
            if err:
                add('FGT-ACL-001', 'ACL_MGMT', 'high', title, 'ERROR', err, item=str(net))
                continue
            obj = _fgt_find(rows, 'name', name)
            problems = []
            if not obj:
                problems.append(u'objeto não encontrado')
            elif _norm_net(_fgt_get(obj, 'subnet')) != _norm_net(net):
                problems.append(u'subnet: esperado %s, encontrado %s' % (fortios_ipmask(net), _fgt_get(obj, 'subnet')))
            judge('FGT-ACL-001', 'ACL_MGMT', 'high', title, problems, u'subnet %s' % fortios_ipmask(net), rem, str(net))

        group = str(acl.get('addrgrp'))
        rows, err = _fgt_table(facts, 'firewall_addrgrp')
        want_members = set(fortios_addr_name(n, prefix) for n in networks)
        title = u'Grupo de endereços "%s" = redes de gerência' % group
        if err:
            add('FGT-ACL-002', 'ACL_MGMT', 'high', title, 'ERROR', err)
        else:
            grp = _fgt_find(rows, 'name', group)
            have = set(_fgt_names(_fgt_get(grp, 'member'))) if grp else set()
            problems = []
            if not grp:
                problems.append(u'grupo não encontrado')
            elif have != want_members:
                if want_members - have:
                    problems.append(u'faltando: %s' % ', '.join(sorted(want_members - have)))
                if have - want_members:
                    problems.append(u'sobrando: %s' % ', '.join(sorted(have - want_members)))
            judge('FGT-ACL-002', 'ACL_MGMT', 'high', title, problems, u'%d membro(s) conforme(s)' % len(have), rem)

        want_hosts = set(_norm_net(n) for n in networks)
        if _to_bool(acl.get('trusthost', False), False) and _to_bool(tac.get('enabled', False), False):
            title = u'Trusthosts do admin remoto "%s"' % tac.get('admin')
            if admin_obj is None:
                add('FGT-ACL-003', 'ACL_MGMT', 'high', title, 'FAIL', u'administrador não encontrado', rem)
            else:
                have = _fgt_trusthosts(admin_obj)
                judge('FGT-ACL-003', 'ACL_MGMT', 'high', title,
                      [] if have == want_hosts else [u'esperado %s, encontrado %s' % (sorted(want_hosts), sorted(have) or 'qualquer origem')],
                      u'%d trusthost(s) conforme(s)' % len(have), rem)

        local_admins = list(acl.get('local_admins') or [])
        if local_admins:
            rows, err = _fgt_table(facts, 'system_admin')
            for name in local_admins:
                title = u'Trusthosts do admin local "%s"' % name
                if err:
                    add('FGT-ACL-004', 'ACL_MGMT', 'high', title, 'ERROR', err, item=str(name))
                    continue
                obj = _fgt_find(rows, 'name', name)
                if not obj:
                    add('FGT-ACL-004', 'ACL_MGMT', 'high', title, 'FAIL', u'administrador não existe', rem, str(name))
                    continue
                have = _fgt_trusthosts(obj)
                judge('FGT-ACL-004', 'ACL_MGMT', 'high', title,
                      [] if have == want_hosts else [u'esperado %s, encontrado %s' % (sorted(want_hosts), sorted(have) or 'qualquer origem')],
                      u'%d trusthost(s) conforme(s)' % len(have), rem, str(name))

        if _to_bool(acl.get('localin', False), False):
            rows, err = _fgt_table(facts, 'firewall_local-in-policy')
            for pol in fortios_localin_policies(acl.get('localin_interfaces'), acl.get('localin_opts')):
                intf = pol.get('intf') or pol['intf_dict'][0]['name']
                accept = pol['action'] == 'accept'
                cid = 'FGT-ACL-005' if accept else 'FGT-ACL-006'
                title = (u'Local-in %s: permite %s em %s' % (pol['policyid'], pol['srcaddr'][0]['name'], intf) if accept
                         else u'Local-in %s: bloqueia demais origens em %s' % (pol['policyid'], intf))
                if err:
                    add(cid, 'ACL_MGMT', 'high', title, 'ERROR', err, item=str(intf))
                    continue
                obj = _fgt_find(rows, 'policyid', pol['policyid'])
                problems = []
                if not obj:
                    problems.append(u'policy %s não encontrada' % pol['policyid'])
                else:
                    diff(obj, 'action', pol['action'], problems)
                    diff(obj, 'status', 'enable', problems)
                    have_intf = _fgt_names(_fgt_get(obj, 'intf')) or _fgt_names(_fgt_get(obj, 'intf_dict'))
                    if [intf] != have_intf:
                        problems.append(u'intf: esperado %s, encontrado %s' % (intf, have_intf))
                    if _fgt_names(_fgt_get(obj, 'srcaddr')) != [pol['srcaddr'][0]['name']]:
                        problems.append(u'srcaddr: esperado %s, encontrado %s'
                                        % (pol['srcaddr'][0]['name'], _fgt_names(_fgt_get(obj, 'srcaddr'))))
                    want_svc = set(s['name'] for s in pol['service'])
                    have_svc = set(_fgt_names(_fgt_get(obj, 'service')))
                    if want_svc != have_svc:
                        problems.append(u'service: esperado %s, encontrado %s' % (sorted(want_svc), sorted(have_svc)))
                judge(cid, 'ACL_MGMT', 'high', title, problems, u'Policy conforme', rem, str(intf))
    return out


class FilterModule(object):
    """Filtros do baseline de gerência (sanity check + FortiOS)."""

    def filters(self):
        return {
            # engine
            'netbaseline_evaluate': netbaseline_evaluate,
            'netbaseline_sources': netbaseline_sources,
            'netbaseline_collect_outputs': netbaseline_collect_outputs,
            'netbaseline_host_digest': netbaseline_host_digest,
            'netbaseline_blocking': netbaseline_blocking,
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
            'fortios_collect_facts': fortios_collect_facts,
            'fortios_fact_errors': fortios_fact_errors,
            'fortios_table_names': fortios_table_names,
            'fortios_baseline_evaluate': fortios_baseline_evaluate,
        }
