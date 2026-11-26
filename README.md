# network-mgmt-baseline

Automação Ansible do **plano de gerência** dos equipamentos de rede:

| Playbook | Plataformas | O que faz |
|---|---|---|
| `sanity_check.yml` | Cisco IOS / IOS-XE / NX-OS, Huawei VRP | **Valida** (só leitura) ACL de gerência e TACACS+ |
| `fortinet_baseline.yml` | FortiGate | **Implementa** TACACS+, Syslog e ACL de gerência |

Na validação, cada equipamento lista na saída do Ansible as não conformidades com severidade,
detalhe e **remediação sugerida** (comandos). Versão para **lab**: sem criptografia, sem backup e
sem verificação pós-mudança.

## Estrutura

```
ansible.cfg                       # inventário padrão, timeouts, plugins
requirements.yml                  # coleções Ansible
sanity_check.yml                  # playbook de validação (Cisco/Huawei)
fortinet_baseline.yml             # playbook de implementação (FortiGate)
inventories/producao/
  hosts.yml                       # equipamentos (um exemplo por plataforma)
  group_vars/all/baseline.yml     # FONTE DA VERDADE: redes de gerência, TACACS+, Syslog, critérios
  group_vars/all/credenciais.yml  # senhas e chaves (criar a partir do .example; fora do Git)
  group_vars/<plataforma>.yml     # conexão + nomes esperados (grupo AAA, ACL, template HWTACACS...)
roles/network_sanity_check/       # validação: tasks + regras por fabricante (vars/*.yml)
roles/fortinet_mgmt_baseline/     # implementação FortiGate: tasks/main.yml (etapas 1 a 5)
filter_plugins/netbaseline.py     # lógica de avaliação e helpers FortiOS (não precisa editar)
```

## Instalação

```bash
python3 -m pip install ansible-core ansible-pylibssh
ansible-galaxy collection install -r requirements.yml -p ./collections
cp inventories/producao/group_vars/all/credenciais.yml.example inventories/producao/group_vars/all/credenciais.yml
```

- ansible-core **2.16+**.
- `credenciais.yml` é texto simples e está no `.gitignore`: as senhas ficam só na sua máquina.
- FortiGate: um **REST API Admin** com token (System > Administrators).
- Cisco/Huawei: usuário SSH que possa rodar `show running-config` / `display current-configuration`.
- Projeto numa pasta do Windows usada pelo WSL (`/mnt/c/...`): rode
  `export ANSIBLE_CONFIG=$PWD/ansible.cfg`, senão o Ansible ignora o `ansible.cfg`.

> Os módulos `community.general.hwc_*` são da **Huawei Cloud** e não servem para switches/roteadores.
> Para o VRP usamos SSH com o plugin `community.network.ce` (coleção depreciada, mas ainda
> instalável; versão fixada em `<6.0.0` no `requirements.yml`).

## Configuração

Edite `group_vars/all/baseline.yml`:

```yaml
mgmt_networks:                    # IPv4 em CIDR (/32 = host)
  - 10.10.0.0/16
  - 192.168.100.10/32
tacacs_servers:                   # ordem = primário, secundário, terciário
  - { name: ISE-01, ip: 10.20.0.11 }
  - { name: ISE-02, ip: 10.20.0.12 }
syslog_servers:                   # FortiGate: até 4
  - { ip: 10.30.0.50, port: 514 }
```

Critérios da validação (`true/false`): `sanity_require_local_fallback`,
`sanity_require_cmd_authorization`, `sanity_require_accounting`, `sanity_require_ssh_only`,
`sanity_require_explicit_deny`, `sanity_runtime_checks`.

## Uso

```bash
# Validação Cisco/Huawei (só leitura)
ansible-playbook sanity_check.yml
ansible-playbook sanity_check.yml -l huawei_vrp

# FortiGate
ansible-playbook fortinet_baseline.yml --check --diff     # só mostra o que mudaria
ansible-playbook fortinet_baseline.yml                    # aplica
ansible-playbook fortinet_baseline.yml --tags syslog      # só uma parte (tacacs | syslog | acl)
```

Saída por equipamento:

```
[FAIL][critical] IOS-ACL-005 - Todas as line vty com access-class ACL-MGMT in: 1 de 2 seção(ões) fora do padrão: line vty 5 15
```

## FortiGate: etapas (`roles/fortinet_mgmt_baseline/tasks/main.yml`)

1. **Anti-lockout**: aborta sem mexer em nada se `fortinet_controller_ip` (o IP com que o
   FortiGate vê o Ansible) não estiver em `mgmt_networks`.
2. **Objetos**: `firewall address` `MGMT_<rede>_<prefixo>` + `addrgrp` `GRP-MGMT-ACCESS`.
3. **TACACS+**: `user tacacs+` (até 3 servidores), `user group`, `system admin` wildcard
   (remote-auth, accprofile, trusthosts) e `log tacacs+accounting setting`.
4. **Syslog**: `log syslogd[2-4] setting` + filtro de severidade; slots sem servidor desativados.
5. **Local-in** por interface: accept de `GRP-MGMT-ACCESS` + deny das demais origens
   (HTTPS/SSH/PING). É a etapa mais sensível, por isso fica por último.

**Atenção:**
- Não aplique a local-in em interface onde a **SSL-VPN** usa a mesma porta do HTTPS de administração.
- IDs de local-in a partir de `fortinet_localin_policyid_base` (900) são sobrescritos.
- FortiOS **7.6+**: `fortinet_localin_intf_format: list`.
- Multi-VDOM: syslog/accounting são globais, valide em lab. Escopo IPv4.

## Regras da validação

Cada regra está em `roles/network_sanity_check/vars/<plataforma>.yml`. Para adicionar uma,
basta incluir um item:

```yaml
- id: IOS-ACL-002
  category: ACL_MGMT
  severity: high
  title: "Rede de gerência __CIDR__ permitida na {{ ios_mgmt_acl }}"
  type: any_section                 # present | absent | any_section | each_section | each_section_absent
  items: "{{ mgmt_networks }}"      # roda 1x por item
  section: "{{ _ios_acl_section }}" # regex da linha que abre a seção
  pattern: '\bpermit\s+(?:(?:ip|tcp)\s+)?__CISCO_SRC__(?:\s|$)'
  remediation: |-
    ip access-list standard {{ ios_mgmt_acl }}
     permit __CISCO_SRC__
```

Placeholders por item: `__IP__ __CIDR__ __MASK__ __WILDCARD__ __PREFIX__ __CISCO_SRC__
__HUAWEI_SRC__ __NAME__ __LABEL__`.

**Cisco IOS / IOS-XE** — `show running-config`

| ID | Categoria | Severidade | Verificação |
|---|---|---|---|
| IOS-TAC-001 | TACACS | Crítica | AAA new-model habilitado |
| IOS-TAC-002 | TACACS | Crítica | Servidor TACACS+ {servidor} configurado |
| IOS-TAC-003 | TACACS | Alta | Servidor {servidor} membro do grupo ISE-TACACS |
| IOS-TAC-004 | TACACS | Crítica | Login via TACACS+ (default) com fallback local |
| IOS-TAC-005 | TACACS | Alta | Autorização exec via TACACS+ |
| IOS-TAC-006 | TACACS | Média | Autorização de comandos (privilégio 15) via TACACS+ |
| IOS-TAC-007 | TACACS | Média | Accounting de sessões (exec) via TACACS+ |
| IOS-TAC-008 | TACACS | Média | Accounting de comandos (privilégio 15) via TACACS+ |
| IOS-TAC-009 | TACACS | Baixa | Source-interface TACACS+ *(se `ios_tacacs_source_interface` definido)* |
| IOS-TAC-010 | TACACS | Média | Chave TACACS+ não está em texto claro (tacacs server) |
| IOS-TAC-011 | TACACS | Média | Chave TACACS+ não está em texto claro (sintaxe legada) |
| IOS-TAC-012 | TACACS | Alta | Servidores TACACS+ sem status Dead (show tacacs) |
| IOS-ACL-001 | ACL_MGMT | Crítica | ACL de gerência ACL-MGMT existe |
| IOS-ACL-002 | ACL_MGMT | Alta | Rede de gerência {rede} permitida na ACL-MGMT |
| IOS-ACL-003 | ACL_MGMT | Crítica | ACL ACL-MGMT não contém permit any |
| IOS-ACL-004 | ACL_MGMT | Baixa | ACL ACL-MGMT termina com deny explícito *(opcional)* |
| IOS-ACL-005 | ACL_MGMT | Crítica | Todas as line vty com access-class ACL-MGMT in |
| IOS-ACL-006 | ACL_MGMT | Alta | Todas as line vty aceitam somente SSH |
| IOS-ACL-007 | TACACS | Crítica | Line vty usam a method list default *(opcional)* |
| IOS-ACL-008 | ACL_MGMT | Baixa | SSH versão 2 |

**Cisco NX-OS** — `show running-config`

| ID | Categoria | Severidade | Verificação |
|---|---|---|---|
| NX-TAC-001 | TACACS | Crítica | feature tacacs+ habilitada |
| NX-TAC-002 | TACACS | Crítica | Servidor TACACS+ {servidor} configurado |
| NX-TAC-003 | TACACS | Alta | Servidor {servidor} membro do grupo ISE-TACACS |
| NX-TAC-004 | TACACS | Alta | Grupo ISE-TACACS usa a VRF management |
| NX-TAC-005 | TACACS | Baixa | Source-interface TACACS+ *(se `nxos_tacacs_source_interface` definido)* |
| NX-TAC-006 | TACACS | Crítica | Login via TACACS+ (aaa authentication login default) |
| NX-TAC-007 | TACACS | Média | Autorização de comandos via TACACS+ |
| NX-TAC-008 | TACACS | Média | Accounting via TACACS+ |
| NX-ACL-001 | ACL_MGMT | Crítica | ACL de gerência ACL-MGMT existe |
| NX-ACL-002 | ACL_MGMT | Alta | Rede de gerência {rede} permitida na ACL-MGMT |
| NX-ACL-003 | ACL_MGMT | Crítica | ACL ACL-MGMT não contém permit any |
| NX-ACL-004 | ACL_MGMT | Baixa | ACL ACL-MGMT termina com deny explícito *(opcional)* |
| NX-ACL-005 | ACL_MGMT | Crítica | line vty com access-class ACL-MGMT in |
| NX-ACL-006 | ACL_MGMT | Alta | Telnet desabilitado (feature telnet ausente) |

**Huawei VRP** — `display current-configuration`

| ID | Categoria | Severidade | Verificação |
|---|---|---|---|
| HW-TAC-001 | TACACS | Crítica | Template HWTACACS ISE existe |
| HW-TAC-002 | TACACS | Crítica | Servidor de autenticação {servidor} no template |
| HW-TAC-003 | TACACS | Alta | Servidor de autorização {servidor} no template |
| HW-TAC-004 | TACACS | Média | Servidor de accounting {servidor} no template |
| HW-TAC-005 | TACACS | Alta | Shared-key do template armazenada cifrada |
| HW-TAC-006 | TACACS | Crítica | authentication-scheme TACACS usa HWTACACS com fallback local |
| HW-TAC-007 | TACACS | Alta | authorization-scheme TACACS usa HWTACACS |
| HW-TAC-008 | TACACS | Média | Autorização de comandos (authorization-cmd) via HWTACACS |
| HW-TAC-009 | TACACS | Média | accounting-scheme TACACS usa HWTACACS |
| HW-TAC-010 | TACACS | Crítica | Domínio default_admin usa o template ISE |
| HW-TAC-011 | TACACS | Crítica | Domínio default_admin usa authentication-scheme TACACS |
| HW-TAC-012 | TACACS | Alta | Domínio default_admin usa authorization-scheme TACACS |
| HW-TAC-013 | TACACS | Média | Domínio default_admin usa accounting-scheme TACACS |
| HW-TAC-014 | TACACS | Crítica | Todas as user-interface vty com authentication-mode aaa |
| HW-ACL-001 | ACL_MGMT | Crítica | ACL de gerência 2000 existe |
| HW-ACL-002 | ACL_MGMT | Alta | Rede de gerência {rede} permitida na ACL 2000 |
| HW-ACL-003 | ACL_MGMT | Crítica | ACL 2000 não contém permit irrestrito |
| HW-ACL-004 | ACL_MGMT | Baixa | ACL 2000 termina com deny explícito *(opcional)* |
| HW-ACL-005 | ACL_MGMT | Crítica | Todas as user-interface vty com acl 2000 inbound |
| HW-ACL-006 | ACL_MGMT | Alta | Todas as user-interface vty aceitam somente SSH |
| HW-ACL-007 | ACL_MGMT | Média | Servidor Telnet desabilitado |
| HW-ACL-008 | ACL_MGMT | Média | Servidor STelnet (SSH) habilitado |

**Limites:** os regex cobrem as sintaxes mais comuns de IOS-XE 16/17, IOS 15, NX-OS 9/10 e
VRP V200. Se aparecer falso positivo no seu lab, ajuste a regra em `vars/<plataforma>.yml`.
