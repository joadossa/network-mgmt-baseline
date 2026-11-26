# -*- coding: utf-8 -*-
"""Engine de regras do sanity check (Cisco IOS/IOS-XE, NX-OS, Huawei VRP).

Avalia as regras de roles/network_sanity_check/vars/<plataforma>.yml contra a
saída dos comandos e devolve PASS / FAIL / ERROR por regra.

Tipos de regra:
  present             -> 'pattern' precisa aparecer na saída
  absent              -> 'pattern' não pode aparecer
  any_section         -> pelo menos uma seção ('section') contém 'pattern'
  each_section        -> todas as seções contêm 'pattern'
  each_section_absent -> nenhuma seção contém 'pattern'
"""
import ipaddress
import re

PLACEHOLDER = re.compile(r'__([A-Z_]+?)__')
PAGING = re.compile(r'--+\s*More\s*--+', re.IGNORECASE)
MAX_LINES = 5


def _on(value):
    """Campo 'enabled' das regras: aceita bool ou texto."""
    return str(value).strip().lower() in ('true', 'yes', '1')


def _placeholders(item):
    """Valores dos __X__ para um item da lista 'items': (texto puro, versão regex)."""
    if item is None:
        return {}, {}
    if isinstance(item, dict):                      # ex.: {name: ISE-01, ip: 10.20.0.11}
        raw = dict((k.upper(), str(v)) for k, v in item.items())
        label = str(item.get('ip') or item.get('name'))
    else:                                           # ex.: '10.10.0.0/16'
        raw, label = {}, str(item)
    raw.setdefault('NAME', label)
    raw['LABEL'] = label
    rx = dict((k, re.escape(v)) for k, v in raw.items())
    try:
        net = ipaddress.ip_network(label, strict=False)
    except ValueError:
        return raw, rx
    ip, wildcard, prefix = str(net.network_address), str(net.hostmask), str(net.prefixlen)
    raw.update(IP=ip, CIDR=ip + '/' + prefix, MASK=str(net.netmask), WILDCARD=wildcard)
    rx.update((k, re.escape(raw[k])) for k in ('IP', 'CIDR', 'MASK', 'WILDCARD'))
    e_ip = re.escape(ip)
    if net.prefixlen == 32:
        # host -> Cisco: "host X" ou "X"  |  Huawei: "X 0", "X 0.0.0.0" ou "X/32"
        raw['CISCO_SRC'], rx['CISCO_SRC'] = 'host ' + ip, r'(?:host\s+%s|%s(?:\s+0\.0\.0\.0)?(?!\s+\d))' % (e_ip, e_ip)
        raw['HUAWEI_SRC'], rx['HUAWEI_SRC'] = ip + ' 0', r'%s(?:\s+(?:0|0\.0\.0\.0|32)|/32)' % e_ip
    else:
        raw['CISCO_SRC'] = raw['HUAWEI_SRC'] = ip + ' ' + wildcard
        rx['CISCO_SRC'] = r'%s\s+%s' % (e_ip, re.escape(wildcard))
        rx['HUAWEI_SRC'] = r'%s(?:\s+(?:%s|%s)|/%s)' % (e_ip, re.escape(wildcard), prefix, prefix)
    return raw, rx


def _fill(text, values):
    """Troca os __X__ pelos valores (KeyError se faltar algum)."""
    return PLACEHOLDER.sub(lambda m: values[m.group(1)], str(text or ''))


def _sections(lines, start):
    """Seção = linha que casa com 'start' + as linhas seguintes mais indentadas
    (vale para IOS, NX-OS e VRP, inclusive aninhadas: aaa > domain > ...)."""
    found, i = [], 0
    while i < len(lines):
        if lines[i].strip() and start.search(lines[i]):
            indent = len(lines[i]) - len(lines[i].lstrip())
            j = i + 1
            while j < len(lines) and lines[j].strip() and len(lines[j]) - len(lines[j].lstrip()) > indent:
                j += 1
            found.append(lines[i:j])
            i = j
        else:
            i += 1
    return found


def _hits(lines, rx):
    return [line.strip() for line in lines if rx.search(line)][:MAX_LINES]


def _run(rule, rx_values, outputs, default_source):
    """Aplica uma regra e devolve (status, detalhe)."""
    source = rule.get('source', default_source)
    out = outputs.get(source, {'ok': False, 'msg': 'comando não executado'})
    if not out['ok']:
        return 'ERROR', 'falha em "%s": %s' % (source, out['msg'])
    if PAGING.search(out['stdout']):
        return 'ERROR', 'paginação na saída de "%s" (terminal length / screen-length)' % source
    if source == default_source and not out['stdout'].strip():
        return 'ERROR', 'saída vazia de "%s"' % source

    flags = re.M | (re.I if 'i' in str(rule.get('flags', '')) else 0)
    pattern = re.compile(_fill(rule['pattern'], rx_values), flags)
    lines = [line.rstrip() for line in out['stdout'].splitlines()]
    kind = rule.get('type', 'present')

    if kind == 'present':
        hits = _hits(lines, pattern)
        return ('PASS', 'encontrado: ' + ' | '.join(hits)) if hits else ('FAIL', 'não encontrado')
    if kind == 'absent':
        hits = _hits(lines, pattern)
        return ('FAIL', 'não permitido: ' + ' | '.join(hits)) if hits else ('PASS', 'nenhuma ocorrência')

    sections = _sections(lines, re.compile(_fill(rule['section'], rx_values), flags))
    headers = lambda secs: ', '.join(s[0].strip() for s in secs[:MAX_LINES])
    if kind == 'each_section_absent':
        bad = [s for s in sections if _hits(s, pattern)]
        return ('FAIL', 'não permitido em: ' + headers(bad)) if bad else ('PASS', '%d seção(ões) ok' % len(sections))
    if not sections:
        return 'FAIL', 'seção não encontrada'
    if kind == 'any_section':
        good = [s for s in sections if _hits(s, pattern)]
        return ('PASS', 'encontrado em: ' + headers(good)) if good else ('FAIL', 'nenhuma seção tem o esperado: ' + headers(sections))
    if kind == 'each_section':
        bad = [s for s in sections if not _hits(s, pattern)]
        if bad:
            return 'FAIL', '%d de %d fora do padrão: %s' % (len(bad), len(sections), headers(bad))
        return 'PASS', '%d seção(ões) ok: %s' % (len(sections), headers(sections))
    return 'ERROR', 'tipo de regra desconhecido: %s' % kind


def netbaseline_evaluate(outputs, rules, default_source):
    """Roda as regras habilitadas; regras com 'items' rodam uma vez por item."""
    results = []
    for rule in rules:
        if not _on(rule.get('enabled', True)):
            continue
        for item in rule.get('items', [None]):
            raw, rx = _placeholders(item)
            label = raw.get('LABEL')
            result = {'id': rule['id'] + ('[%s]' % label if label else ''),
                      'severity': rule.get('severity', 'medium'),
                      'title': rule.get('title', rule['id']), 'remediation': ''}
            try:
                result['title'] = _fill(result['title'], raw)
                result['remediation'] = _fill(rule.get('remediation'), raw)
                result['status'], result['detail'] = _run(rule, rx, outputs, default_source)
            except KeyError as exc:
                result['status'], result['detail'] = 'ERROR', 'campo ou placeholder sem valor: %s' % exc
            except re.error as exc:
                result['status'], result['detail'] = 'ERROR', 'regex inválido: %s' % exc
            results.append(result)
    return results


def netbaseline_sources(rules, default_source):
    """Comandos a executar: a configuração + os 'source' extras das regras habilitadas."""
    commands = [default_source]
    for rule in rules:
        source = rule.get('source')
        if source and source not in commands and _on(rule.get('enabled', True)):
            commands.append(source)
    return commands


def netbaseline_collect_outputs(results):
    """'register' do loop de cli_command -> {comando: {ok, stdout, msg}}."""
    return dict((r['item'], {'ok': not r.get('failed'), 'stdout': r.get('stdout', ''), 'msg': r.get('msg', '')})
                for r in results)


def netbaseline_host_digest(results):
    """Linhas para o debug: só o que não passou, com a correção sugerida."""
    out = []
    for r in results:
        if r['status'] != 'PASS':
            line = '[%s][%s] %s - %s: %s' % (r['status'], r['severity'], r['id'], r['title'], r['detail'])
            if r['status'] == 'FAIL' and r['remediation']:
                line += '\n  correção:\n    ' + r['remediation'].replace('\n', '\n    ')
            out.append(line)
    return out or ['Tudo conforme (%d regras)' % len(results)]


class FilterModule(object):
    def filters(self):
        return {
            'netbaseline_evaluate': netbaseline_evaluate,
            'netbaseline_sources': netbaseline_sources,
            'netbaseline_collect_outputs': netbaseline_collect_outputs,
            'netbaseline_host_digest': netbaseline_host_digest,
        }
