#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          VULNMAPPER v2.0  —  FREE INTELLIGENCE TOOL          ║
║     CVE (NVD)  ·  MITRE ATT&CK  ·  Exploit-DB               ║
║     No API key needed  ·  Works offline (MITRE)              ║
╚══════════════════════════════════════════════════════════════╝

Usage:
  python vulnmapper.py apache 2.4.49
  python vulnmapper.py log4j 2.14.1 --report
  python vulnmapper.py openssh 7.2p2 --json results.json
  python vulnmapper.py struts 2.3.5 --max 30
  python vulnmapper.py --help             # display help menu
  python vulnmapper.py --install          # auto-install deps
"""

import sys, os, json, time, csv, io, re, argparse, subprocess
import webbrowser, urllib.parse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

# ── dependency check ──────────────────────────────────────────
MISSING = []
try:
    import requests
except ImportError:
    MISSING.append('requests')

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.rule import Rule
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH = True
    console = Console()
except ImportError:
    MISSING.append('rich')
    RICH = False
    import re as _re
    class _FakeCon:
        def print(self, *a, **kw):
            txt = ' '.join(str(x) for x in a)
            txt = _re.sub(r'\[/?[^\]]*\]', '', txt)
            print(txt)
        def rule(self, t='', **kw): print(f"─── {_re.sub(r'.+.', '', t)} " + '─'*40)
    console = _FakeCon()

# ═══════════════════════════════════════════════════════════════
#  BUILT-IN MITRE ATT&CK DATABASE  (works 100% offline)
# ═══════════════════════════════════════════════════════════════

MITRE = {
  'T1595':     ('Active Scanning',                      'Reconnaissance',        'TA0043', 'Adversaries actively scan victim infrastructure to gather info (Nmap, Shodan, Masscan).'),
  'T1592':     ('Gather Victim Host Info',              'Reconnaissance',        'TA0043', 'Adversaries gather info about the victim host: OS, software, hardware, configs.'),
  'T1590':     ('Gather Victim Network Info',           'Reconnaissance',        'TA0043', 'Adversaries gather info about victim network: IP ranges, topology, DNS.'),
  'T1190':     ('Exploit Public-Facing Application',    'Initial Access',        'TA0001', 'Adversaries exploit weaknesses in Internet-facing software to gain initial foothold.'),
  'T1078':     ('Valid Accounts',                       'Initial Access',        'TA0001', 'Adversaries obtain and abuse credentials of existing accounts.'),
  'T1133':     ('External Remote Services',             'Initial Access',        'TA0001', 'Adversaries leverage external-facing remote services (VPN, RDP, SSH) with valid accounts.'),
  'T1059':     ('Command and Scripting Interpreter',    'Execution',             'TA0002', 'Adversaries abuse command interpreters to execute commands, scripts, or binaries.'),
  'T1059.001': ('PowerShell',                           'Execution',             'TA0002', 'Adversaries abuse PowerShell for execution, bypass, and living-off-the-land.'),
  'T1059.004': ('Unix Shell',                           'Execution',             'TA0002', 'Adversaries execute commands via Unix shell (bash, sh, zsh) on Linux/macOS.'),
  'T1059.007': ('JavaScript',                           'Execution',             'TA0002', 'Adversaries abuse JavaScript via browsers or server-side runtimes.'),
  'T1059.006': ('Python',                               'Execution',             'TA0002', 'Adversaries use Python scripts for execution and post-exploitation.'),
  'T1203':     ('Exploitation for Client Execution',    'Execution',             'TA0002', 'Adversaries exploit vulnerabilities in client-side apps to execute code.'),
  'T1210':     ('Exploitation of Remote Services',      'Lateral Movement',      'TA0008', 'Adversaries exploit network services to pivot deeper into a network.'),
  'T1505.003': ('Web Shell',                            'Persistence',           'TA0003', 'Adversaries upload web shells to web servers for persistent backdoor access.'),
  'T1543':     ('Create/Modify System Process',         'Persistence',           'TA0003', 'Adversaries create or modify system-level processes for persistence.'),
  'T1053':     ('Scheduled Task/Job',                   'Persistence',           'TA0003', 'Adversaries abuse task schedulers (cron, at, schtasks) to persist.'),
  'T1068':     ('Exploitation for Privilege Escalation','Privilege Escalation',  'TA0004', 'Adversaries exploit vulnerabilities to gain higher system privileges.'),
  'T1055':     ('Process Injection',                    'Defense Evasion',       'TA0005', 'Adversaries inject code into running processes to evade detection.'),
  'T1222':     ('File/Directory Permissions Mod',       'Defense Evasion',       'TA0005', 'Adversaries modify permissions to evade access control.'),
  'T1140':     ('Deobfuscate/Decode Files',             'Defense Evasion',       'TA0005', 'Adversaries decode/deobfuscate payloads to evade signature detection.'),
  'T1110':     ('Brute Force',                          'Credential Access',     'TA0006', 'Adversaries use brute force techniques to gain access to accounts.'),
  'T1110.001': ('Password Guessing',                    'Credential Access',     'TA0006', 'Adversaries systematically guess passwords to gain access.'),
  'T1110.004': ('Credential Stuffing',                  'Credential Access',     'TA0006', 'Adversaries use credentials from breach dumps.'),
  'T1212':     ('Exploitation for Credential Access',   'Credential Access',     'TA0006', 'Adversaries exploit vulnerabilities to collect credentials from memory.'),
  'T1552':     ('Unsecured Credentials',                'Credential Access',     'TA0006', 'Adversaries search for credentials stored insecurely in files, env vars, etc.'),
  'T1083':     ('File and Directory Discovery',         'Discovery',             'TA0007', 'Adversaries enumerate files and directories for sensitive information.'),
  'T1046':     ('Network Service Discovery',            'Discovery',             'TA0007', 'Adversaries enumerate network services available on a host.'),
  'T1021.001': ('Remote Desktop Protocol',              'Lateral Movement',      'TA0008', 'Adversaries use RDP with valid credentials to access remote machines.'),
  'T1021.002': ('SMB/Windows Admin Shares',             'Lateral Movement',      'TA0008', 'Adversaries use SMB to move laterally and transfer files.'),
  'T1021.004': ('SSH',                                  'Lateral Movement',      'TA0008', 'Adversaries use SSH to log into remote machines.'),
  'T1570':     ('Lateral Tool Transfer',                'Lateral Movement',      'TA0008', 'Adversaries transfer tools between systems in a compromised network.'),
  'T1213':     ('Data from Information Repositories',   'Collection',            'TA0009', 'Adversaries mine information repositories for sensitive data.'),
  'T1557':     ('Adversary-in-the-Middle',              'Collection',            'TA0009', 'Adversaries intercept traffic between two hosts.'),
  'T1041':     ('Exfiltration Over C2 Channel',         'Exfiltration',          'TA0010', 'Adversaries exfiltrate data over the existing C2 channel.'),
  'T1090':     ('Proxy',                                'Command and Control',   'TA0011', 'Adversaries use proxies to relay C2 traffic and obscure origin.'),
  'T1071.001': ('Web Protocols',                        'Command and Control',   'TA0011', 'Adversaries use HTTP/HTTPS for C2 communication to blend with normal traffic.'),
  'T1499':     ('Endpoint Denial of Service',           'Impact',                'TA0040', 'Adversaries degrade or block service availability via DoS.'),
  'T1485':     ('Data Destruction',                     'Impact',                'TA0040', 'Adversaries destroy data on systems to interrupt operations.'),
  'T1486':     ('Data Encrypted for Impact',            'Impact',                'TA0040', 'Adversaries encrypt data (ransomware) to extort victims.'),
  'T1489':     ('Service Stop',                         'Impact',                'TA0040', 'Adversaries stop or disable services to interrupt availability.'),
}

CWE_MAP = {
  'CWE-22':  ['T1190', 'T1055', 'T1083'],
  'CWE-78':  ['T1059.004', 'T1059', 'T1190'],
  'CWE-79':  ['T1059.007'],
  'CWE-89':  ['T1190', 'T1213'],
  'CWE-94':  ['T1059', 'T1190'],
  'CWE-119': ['T1203', 'T1190'],
  'CWE-120': ['T1203'],
  'CWE-125': ['T1212'],
  'CWE-190': ['T1203'],
  'CWE-200': ['T1083', 'T1213'],
  'CWE-264': ['T1068'],
  'CWE-269': ['T1068'],
  'CWE-276': ['T1222'],
  'CWE-287': ['T1110', 'T1078'],
  'CWE-295': ['T1557'],
  'CWE-306': ['T1078', 'T1133'],
  'CWE-352': ['T1557'],
  'CWE-362': ['T1055'],
  'CWE-400': ['T1499'],
  'CWE-416': ['T1203'],
  'CWE-434': ['T1505.003', 'T1190'],
  'CWE-476': ['T1203'],
  'CWE-502': ['T1059', 'T1190'],
  'CWE-611': ['T1213'],
  'CWE-787': ['T1203'],
  'CWE-798': ['T1078', 'T1552'],
  'CWE-918': ['T1090'],
}

SVC_MAP = {
  'apache':      ['T1190', 'T1059.004', 'T1505.003', 'T1083'],
  'nginx':       ['T1190', 'T1059.004', 'T1083'],
  'iis':         ['T1190', 'T1505.003', 'T1059.001'],
  'tomcat':      ['T1190', 'T1505.003', 'T1059.007'],
  'openssh':     ['T1021.004', 'T1110', 'T1078', 'T1133'],
  'ssh':         ['T1021.004', 'T1110', 'T1078'],
  'wordpress':   ['T1190', 'T1505.003', 'T1059'],
  'drupal':      ['T1190', 'T1505.003', 'T1078'],
  'joomla':      ['T1190', 'T1505.003', 'T1078'],
  'log4j':       ['T1190', 'T1059', 'T1210', 'T1071.001'],
  'log4shell':   ['T1190', 'T1059', 'T1210'],
  'struts':      ['T1190', 'T1059.004', 'T1505.003'],
  'spring':      ['T1190', 'T1059', 'T1210'],
  'jenkins':     ['T1190', 'T1059', 'T1505.003'],
  'mysql':       ['T1190', 'T1213', 'T1078'],
  'postgres':    ['T1190', 'T1213', 'T1078'],
  'mongodb':     ['T1190', 'T1213', 'T1078'],
  'redis':       ['T1190', 'T1505.003', 'T1078'],
  'smb':         ['T1210', 'T1021.002', 'T1570'],
  'samba':       ['T1210', 'T1021.002', 'T1570'],
  'eternal':     ['T1210', 'T1021.002', 'T1570', 'T1486'],
  'rdp':         ['T1021.001', 'T1110.001', 'T1078', 'T1133'],
  'ftp':         ['T1021.002', 'T1078', 'T1083'],
  'php':         ['T1190', 'T1059.006', 'T1505.003'],
  'openssl':     ['T1190', 'T1557', 'T1212'],
  'heartbleed':  ['T1190', 'T1212', 'T1557'],
  'shellshock':  ['T1190', 'T1059.004'],
  'citrix':      ['T1190', 'T1133', 'T1078'],
  'exchange':    ['T1190', 'T1505.003', 'T1213'],
  'ldap':        ['T1190', 'T1213', 'T1078'],
  'vnc':         ['T1021.005', 'T1110', 'T1078'],
  'telnet':      ['T1021.004', 'T1110', 'T1078'],
}

KILL_CHAIN = [
  ('🔍', 'RECONNAISSANCE',        'T1595 · T1592',  'Scan network, fingerprint service + version with Nmap/Shodan/Masscan'),
  ('🚪', 'INITIAL ACCESS',        'T1190 · T1078',  'Exploit identified vulnerability to gain first foothold on target'),
  ('⚡', 'EXECUTION',             'T1059 · T1203',  'Execute payload: reverse shell, command injection, code execution'),
  ('🔒', 'PERSISTENCE',           'T1505 · T1053',  'Deploy web shell, cron job, or service for stable re-access'),
  ('👑', 'PRIVILEGE ESCALATION',  'T1068 · T1055',  'Use local exploit or misconfig to gain root / SYSTEM privileges'),
  ('🛡', 'DEFENSE EVASION',       'T1140 · T1222',  'Clear logs, modify permissions, obfuscate payloads'),
  ('↔', 'LATERAL MOVEMENT',      'T1021 · T1210',  'Pivot from this host to internal network via SSH / SMB / RDP'),
  ('💥', 'IMPACT',                'T1486 · T1485',  'Exfiltrate data, deploy ransomware, destroy evidence'),
]

SEV_ICON = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '⚪'}
SEV_COLOR = {'CRITICAL': 'bold red', 'HIGH': 'bold yellow', 'MEDIUM': 'yellow', 'LOW': 'green', 'UNKNOWN': 'dim'}

NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

def nvd_search(svc: str, ver: str, api_key: str = None, limit: int = 20) -> List[dict]:
    kw = f"{svc} {ver}".strip() if ver else svc
    hdrs = {'apiKey': api_key} if api_key else {}
    try:
        r = requests.get(NVD, params={'keywordSearch': kw, 'resultsPerPage': limit},
                         headers=hdrs, timeout=25)
        r.raise_for_status()
        return r.json().get('vulnerabilities', [])
    except Exception as e:
        console.print(f'[red]NVD error: {e}[/red]')
        return []

def parse_cve(item: dict) -> dict:
    cve = item.get('cve', {})
    cid = cve.get('id', '?')
    desc = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), 'No description.')
    metrics = cve.get('metrics', {})
    score, sev, vec = None, 'UNKNOWN', ''
    for k in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        if metrics.get(k):
            cd = metrics[k][0].get('cvssData', {})
            score = cd.get('baseScore')
            sev = cd.get('baseSeverity') or metrics[k][0].get('baseSeverity', 'UNKNOWN')
            vec = cd.get('vectorString', '')
            break
    cwes = [d['value'] for w in cve.get('weaknesses', [])
             for d in w.get('description', [])
             if d.get('lang') == 'en' and d.get('value', '').startswith('CWE-')]
    return {
        'id': cid, 'description': desc,
        'cvss_score': score, 'severity': (sev or 'UNKNOWN').upper(),
        'vector': vec, 'published': cve.get('published', '')[:10],
        'cwes': cwes,
        'nvd_url': f'https://nvd.nist.gov/vuln/detail/{cid}',
    }

EDB_CSV = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
CACHE_DIR = Path.home() / '.vulnmapper'
CACHE_FILE = CACHE_DIR / 'exploitdb.csv'

def edb_load() -> Optional[io.StringIO]:
    if CACHE_FILE.exists() and (time.time() - CACHE_FILE.stat().st_mtime) < 604800:
        return io.StringIO(CACHE_FILE.read_text(encoding='utf-8', errors='ignore'))
    console.print('[yellow]⬇  Downloading ExploitDB CSV (one-time, ~4 MB, cached 7 days)…[/yellow]')
    try:
        r = requests.get(EDB_CSV, timeout=45, stream=True)
        r.raise_for_status()
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_bytes(r.content)
        return io.StringIO(r.content.decode('utf-8', errors='ignore'))
    except Exception as e:
        console.print(f'[red]ExploitDB download failed: {e}[/red]')
        return None

def edb_search(svc: str, ver: str) -> List[dict]:
    sp = _try_searchsploit(svc, ver)
    if sp is not None:
        return sp
    f = edb_load()
    if not f:
        return []
    results = []
    svc_l = svc.lower()
    try:
        for row in csv.DictReader(f):
            d = (row.get('description') or row.get('Title') or '').lower()
            if svc_l in d and (not ver or ver in d):
                eid = (row.get('id') or row.get('EDB-ID') or '').strip()
                results.append({
                    'edb_id': eid,
                    'title': (row.get('description') or row.get('Title') or '').strip(),
                    'date': (row.get('date_published') or row.get('date') or row.get('Date') or '')[:10],
                    'author': (row.get('author') or row.get('Author') or 'Unknown').strip(),
                    'type': (row.get('type') or row.get('Type') or '').strip(),
                    'platform': (row.get('platform') or row.get('Platform') or '').strip(),
                    'verified': (row.get('verified') or row.get('Verified') or '0') == '1',
                    'url': f'https://www.exploit-db.com/exploits/{eid}',
                })
    except Exception as e:
        console.print(f'[red]ExploitDB parse error: {e}[/red]')
    return results[:12]

def _try_searchsploit(svc: str, ver: str) -> Optional[List[dict]]:
    try:
        q = f"{svc} {ver}" if ver else svc
        out = subprocess.run(['searchsploit', '--json', q], capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            data = json.loads(out.stdout)
            return [{'edb_id': e.get('EDB-ID',''), 'title': e.get('Title',''),
                     'date': e.get('Date',''), 'author': e.get('Author',''),
                     'type': e.get('Type',''), 'platform': e.get('Platform',''),
                     'verified': e.get('Verified','0')=='1',
                     'url': f"https://www.exploit-db.com/exploits/{e.get('EDB-ID','')}"
                    } for e in data.get('RESULTS_EXPLOIT',[])[:12]]
    except:
        pass
    return None

def mitre_map(svc: str, cves: List[dict]) -> List[dict]:
    ids: set = {'T1595', 'T1592', 'T1190'}
    for c in cves:
        for cw in c.get('cwes', []):
            ids.update(CWE_MAP.get(cw, []))
    svc_l = svc.lower()
    for kw, tids in SVC_MAP.items():
        if kw in svc_l:
            ids.update(tids)
    result = []
    for tid in sorted(ids):
        if tid in MITRE:
            nm, tac, tacid, desc = MITRE[tid]
            result.append({'id': tid, 'name': nm, 'tactic': tac, 'tactic_id': tacid,
                           'description': desc,
                           'url': f"https://attack.mitre.org/techniques/{tid.replace('.','/')}"})
    return result

def bar(score, w=22):
    if score is None: return '─' * w
    n = int((score / 10) * w)
    return '█' * n + '░' * (w - n)

def print_banner(svc, ver):
    if RICH:
        console.rule(f'[bold green]⚡ VULNMAPPER  ·  {svc.upper()} {ver}[/bold green]')
        console.print(f'[dim]  NVD · MITRE ATT&CK · Exploit-DB  ·  {datetime.now():%Y-%m-%d %H:%M}[/dim]\n')
    else:
        print('\n' + '═' * 62)
        print(f'  VULNMAPPER  —  {svc.upper()} {ver}')
        print(f'  {datetime.now():%Y-%m-%d %H:%M}')
        print('═' * 62 + '\n')

def print_cves(cves):
    if not cves:
        console.print('[yellow]  No CVEs found for this version.[/yellow]')
        return
    if RICH:
        console.rule(f'[bold cyan]📋 CVE RECORDS  ({len(cves)} found)[/bold cyan]')
        for i, c in enumerate(cves, 1):
            sev = c.get('severity', 'UNKNOWN')
            sc = c.get('cvss_score')
            col = SEV_COLOR.get(sev, 'white')
            icon = SEV_ICON.get(sev, '⚪')
            sc_str = f"{sc:.1f}" if sc else "N/A"
            console.print(f"\n[{col}]  {icon} {c['id']}[/{col}]  "
                          f"[{col}]{sev}[/{col}]  CVSS [{col}]{sc_str}/10[/{col}]  "
                          f"[dim]{c.get('published','')}[/dim]")
            if sc:
                console.print(f"  [{col}]{bar(sc)}[/{col}]  {sc_str}")
            if c.get('cwes'):
                console.print(f"  [dim]CWE: {', '.join(c['cwes'])}[/dim]")
            desc = c.get('description','')
            console.print(f"  {desc[:280]}{'…' if len(desc)>280 else ''}")
            console.print(f"  [blue][link={c['nvd_url']}]{c['nvd_url']}[/link][/blue]")
        console.print()
    else:
        print(f'\n📋 CVE RECORDS ({len(cves)} found)')
        print('─' * 62)
        for c in cves:
            sev = c.get('severity','?'); sc = c.get('cvss_score')
            print(f"\n  [{sev}] {c['id']}  CVSS: {sc or '?'}")
            if c.get('cwes'): print(f"  CWE: {', '.join(c['cwes'])}")
            print(f"  {c.get('description','')[:280]}")
            print(f"  → {c['nvd_url']}")

def print_mitre(techs):
    if not techs:
        console.print('[yellow]  No MITRE techniques found.[/yellow]')
        return
    if RICH:
        console.rule(f'[bold cyan]🗺  MITRE ATT&CK  ({len(techs)} techniques)[/bold cyan]')
        by = {}
        for t in techs: by.setdefault(t['tactic'], []).append(t)
        for tac, ts in by.items():
            console.print(f'\n  [bold yellow]▸ {tac.upper()}[/bold yellow]')
            for t in ts:
                console.print(f"    [bold cyan]{t['id']}[/bold cyan]  {t['name']}")
                console.print(f"    [dim]{t['description'][:160]}[/dim]")
                console.print(f"    [blue]{t['url']}[/blue]")
        console.print()
    else:
        print(f'\n🗺  MITRE ATT&CK ({len(techs)} techniques)')
        print('─' * 62)
        for t in techs:
            print(f"\n  [{t['tactic']}] {t['id']}  {t['name']}")
            print(f"  {t['description'][:160]}")
            print(f"  → {t['url']}")

def print_exploits(exps):
    if not exps:
        if RICH:
            console.print('[bold green]\n  ✓  No public exploits found in Exploit-DB.[/bold green]\n')
        else:
            print('\n✓ No public exploits found.')
        return
    if RICH:
        console.rule(f'[bold red]💥 EXPLOIT-DB  ({len(exps)} exploits)[/bold red]')
        for e in exps:
            ver_tag = '[green]✓ Verified[/green]' if e.get('verified') else ''
            console.print(f"\n  [bold red]EDB-{e['edb_id']}[/bold red]  "
                          f"[yellow]{e.get('type','')}[/yellow]  "
                          f"[dim]{e.get('platform','')}[/dim]  {ver_tag}")
            console.print(f"  [bold]{e.get('title','')[:100]}[/bold]")
            console.print(f"  [dim]👤 {e.get('author','')}  ·  📅 {e.get('date','')}[/dim]")
            console.print(f"  [blue]{e['url']}[/blue]")
        console.print()
    else:
        print(f'\n💥 EXPLOIT-DB ({len(exps)} exploits)')
        print('─' * 62)
        for e in exps:
            print(f"\n  EDB-{e['edb_id']}  [{e.get('type','')}]  {e.get('platform','')}")
            print(f"  {e.get('title','')[:100]}")
            print(f"  Author: {e.get('author','')}  Date: {e.get('date','')}")
            print(f"  → {e['url']}")

def print_chain(svc, cves):
    has_rce = any(any(cw in ['CWE-78','CWE-94','CWE-502','CWE-77']
                       for cw in c.get('cwes',[])) or
                  'rce' in c.get('description','').lower() or
                  'remote code' in c.get('description','').lower()
                  for c in cves)

    if RICH:
        console.rule('[bold cyan]⛓  ATTACK KILL CHAIN[/bold cyan]')
        for icon, phase, techs, default_desc in KILL_CHAIN:
            if phase == 'INITIAL ACCESS':
                desc = f"Exploit {svc} vulnerability, gain first foothold on target"
            elif phase == 'EXECUTION' and not has_rce:
                desc = "Limited code execution – check if target is exploitable"
            else:
                desc = default_desc
            console.print(f"  {icon}  [bold]{phase}[/bold]")
            console.print(f"     [cyan]{techs}[/cyan]")
            console.print(f"     [dim]{desc}[/dim]\n")
    else:
        print('\n⛓  ATTACK KILL CHAIN')
        print('─' * 62)
        for icon, phase, techs, desc in KILL_CHAIN:
            print(f"  {icon}  {phase}  [{techs}]")
            print(f"     {desc}\n")

def print_summary(svc, ver, cves, techs, exps):
    n_crit = sum(1 for c in cves if c.get('severity') == 'CRITICAL')
    n_high = sum(1 for c in cves if c.get('severity') == 'HIGH')
    top_score = max((c.get('cvss_score') or 0 for c in cves), default=0)
    risk = ('🔴 CRITICAL' if top_score >= 9 else '🟠 HIGH' if top_score >= 7 else
            '🟡 MEDIUM' if top_score >= 4 else '🟢 LOW')
    if RICH:
        console.rule('[bold green]SUMMARY[/bold green]')
        console.print(f"""
  Target   : [bold]{svc} {ver}[/bold]
  CVEs     : [red]{len(cves)}[/red]  (Critical: [bold red]{n_crit}[/bold red]  High: [yellow]{n_high}[/yellow])
  ATT&CK   : [cyan]{len(techs)}[/cyan] techniques
  Exploits : [red]{len(exps)}[/red] public
  Risk     : {risk}  (Top CVSS: {top_score})
""")
    else:
        print('\n── SUMMARY ' + '─'*50)
        print(f"  Target: {svc} {ver}")
        print(f"  CVEs: {len(cves)}  (Crit: {n_crit}  High: {n_high})")
        print(f"  ATT&CK: {len(techs)}  Exploits: {len(exps)}")
        print(f"  Risk: {risk}  Top CVSS: {top_score}")
        print()

def html_report(svc, ver, cves, techs, exps) -> str:
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    n_crit = sum(1 for c in cves if c.get('severity') == 'CRITICAL')
    top = max((c.get('cvss_score') or 0 for c in cves), default=0)
    risk_col = '#ff3055' if top >= 9 else '#ff8c00' if top >= 7 else '#f5c518' if top >= 4 else '#00e97a'

    def badge(sev):
        cls = sev.lower() if sev else 'unknown'
        return f'<span class="b {cls}">{sev or "?"}</span>'

    cve_rows = ''.join(f"""<tr>
      <td><a href="{c['nvd_url']}" target="_blank">{c['id']}</a></td>
      <td>{badge(c.get('severity'))}</td>
      <td style="color:{('#ff3055' if (c.get('cvss_score') or 0)>=9 else '#ff8c00' if (c.get('cvss_score') or 0)>=7 else '#f5c518')}">
        {c.get('cvss_score','?')}</td>
      <td>{', '.join(c.get('cwes',[]))}</td>
      <td>{c.get('published','')}</td>
      <td>{c.get('description','')[:220]}</td>
    </tr>""" for c in cves) or '<tr><td colspan="6" class="empty">No CVEs found</td></tr>'

    exp_rows = ''.join(f"""<tr>
      <td><a href="{e['url']}" target="_blank">EDB-{e['edb_id']}</a></td>
      <td>{e.get('title','')[:120]}</td>
      <td>{e.get('author','')}</td>
      <td><span class="b high">{e.get('type','')}</span></td>
      <td>{e.get('platform','')}</td>
      <td>{'✓' if e.get('verified') else ''}</td>
      <td>{e.get('date','')}</td>
    </tr>""" for e in exps) or '<tr><td colspan="7" class="empty">✓ No public exploits found</td></tr>'

    mit_rows = ''.join(f"""<tr>
      <td><a href="{t['url']}" target="_blank">{t['id']}</a></td>
      <td>{t['name']}</td>
      <td><span style="color:#f5c518">{t['tactic']}</span></td>
      <td>{t['description'][:220]}</td>
    </tr>""" for t in techs) or '<tr><td colspan="4" class="empty">No techniques mapped</td></tr>'

    chain_rows = ''.join(f"""<tr>
      <td>{icon}</td><td><b>{ph}</b></td>
      <td style="color:#00bdff;font-size:11px">{tids}</td>
      <td>{desc}</td>
    </tr>""" for icon, ph, tids, desc in KILL_CHAIN)

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnMapper — {svc} {ver}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:#04080f;color:#bfcfe8;padding:24px;font-size:13px}}
h1{{color:#00e97a;font-size:22px;letter-spacing:.06em;margin-bottom:4px}}
.sub{{color:#334870;font-size:10px;letter-spacing:.2em;margin-bottom:20px}}
.stats{{display:flex;gap:12px;margin:18px 0;flex-wrap:wrap}}
.st{{background:#0c1426;border:1px solid #1e3460;padding:14px 18px;text-align:center;min-width:100px}}
.sn{{font-size:26px;font-weight:700;font-family:sans-serif}}
.sl{{font-size:9px;color:#334870;letter-spacing:.18em;text-transform:uppercase;margin-top:3px}}
h2{{color:#00bdff;font-size:11px;letter-spacing:.22em;text-transform:uppercase;
    margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid #1e3460}}
table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:8px}}
th{{background:#0c1426;color:#00bdff;padding:8px 10px;text-align:left;
    border:1px solid #1e3460;font-size:10px;letter-spacing:.1em;font-weight:600}}
td{{padding:8px 10px;border:1px solid #101d36;vertical-align:top;line-height:1.6}}
tr:hover td{{background:#0d1428}}
a{{color:#00bdff;text-decoration:none}}a:hover{{text-decoration:underline}}
.b{{font-size:9px;padding:2px 8px;font-weight:700;letter-spacing:.1em;border:1px solid}}
.b.critical{{background:rgba(255,48,85,.12);color:#ff3055;border-color:#ff3055}}
.b.high{{background:rgba(255,140,0,.12);color:#ff8c00;border-color:#ff8c00}}
.b.medium{{background:rgba(245,197,24,.12);color:#f5c518;border-color:#f5c518}}
.b.low{{background:rgba(0,233,122,.1);color:#00e97a;border-color:#00e97a}}
.empty{{color:#334870;font-style:italic}}
.foot{{margin-top:36px;color:#334870;font-size:10px;letter-spacing:.1em;
       border-top:1px solid #1e3460;padding-top:12px;line-height:1.8}}
</style></head><body>
<h1>⚡ VULNMAPPER REPORT</h1>
<div class="sub">TARGET: {svc.upper()} {ver} &nbsp;·&nbsp; {ts} &nbsp;·&nbsp; NVD · MITRE ATT&amp;CK · EXPLOIT-DB</div>
<div class="stats">
  <div class="st"><div class="sn" style="color:#ff3055">{len(cves)}</div><div class="sl">CVEs</div></div>
  <div class="st"><div class="sn" style="color:#ff3055">{n_crit}</div><div class="sl">Critical</div></div>
  <div class="st"><div class="sn" style="color:#00bdff">{len(techs)}</div><div class="sl">ATT&amp;CK</div></div>
  <div class="st"><div class="sn" style="color:#ff8c00">{len(exps)}</div><div class="sl">Exploits</div></div>
  <div class="st"><div class="sn" style="color:{risk_col}">{top}</div><div class="sl">Top CVSS</div></div>
</div>
<h2>CVE Records ({len(cves)})</h2>
<table><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>CWE</th><th>Published</th><th>Description</th></tr>
{cve_rows}</table>
<h2>Exploit-DB ({len(exps)} public exploits)</h2>
<table><tr><th>EDB-ID</th><th>Title</th><th>Author</th><th>Type</th><th>Platform</th><th>✓</th><th>Date</th></tr>
{exp_rows}</table>
<h2>MITRE ATT&amp;CK Mapping ({len(techs)} techniques)</h2>
<table><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Description</th></tr>
{mit_rows}</table>
<h2>Kill Chain / Attack Path</h2>
<table><tr><th></th><th>Phase</th><th>Techniques</th><th>Description</th></tr>
{chain_rows}</table>
<div class="foot">
  ⚡ VulnMapper — For authorised security research &amp; penetration testing only<br>
  Sources: NVD (NIST) &middot; MITRE ATT&amp;CK &middot; Exploit-DB &middot; Generated: {ts}
</div>
</body></html>"""

def auto_install():
    print('Installing dependencies…')
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests', 'rich', '-q'])
    print('Done! Run vulnmapper again.')
    sys.exit(0)

def main():
    ap = argparse.ArgumentParser(
        prog='vulnmapper',
        description='Free CVE + MITRE ATT&CK + Exploit-DB intelligence tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vulnmapper.py apache 2.4.49
  python vulnmapper.py log4j 2.14.1 --report
  python vulnmapper.py openssh 7.2p2 --json out.json
  python vulnmapper.py struts 2.3.5 --max 30 --report
  python vulnmapper.py --install
        """)
    ap.add_argument('service',  nargs='?', help='Service name (apache, log4j, openssh…)')
    ap.add_argument('version',  nargs='?', default='', help='Version string')
    ap.add_argument('--report', '-r', action='store_true',  help='Generate HTML report (auto-opens in browser)')
    ap.add_argument('--json',   '-j', metavar='FILE',        help='Export full data as JSON')
    ap.add_argument('--max',    '-m', type=int, default=20,  help='Max CVEs from NVD (default: 20)')
    ap.add_argument('--nvd-key',       metavar='KEY',        help='NVD API key for higher rate limit')
    ap.add_argument('--no-exploitdb',  action='store_true',  help='Skip ExploitDB search')
    ap.add_argument('--no-chain',      action='store_true',  help='Skip kill chain display')
    ap.add_argument('--install',       action='store_true',  help='Auto-install pip dependencies')
    args = ap.parse_args()

    if args.install:
        auto_install()

    if not args.service:
        ap.print_help()
        return

    if MISSING:
        print(f"Missing packages: {', '.join(MISSING)}")
        print(f"Run:  python vulnmapper.py --install")
        sys.exit(1)

    svc = args.service
    ver = args.version or ''
    print_banner(svc, ver)

    if RICH:
        with Progress(SpinnerColumn(), TextColumn('[cyan]{task.description}'), console=console) as p:
            t = p.add_task('Querying NVD (NIST)…', total=None)
            raw = nvd_search(svc, ver, args.nvd_key, args.max)
    else:
        print('⟳ Querying NVD…')
        raw = nvd_search(svc, ver, args.nvd_key, args.max)
    cves = sorted([parse_cve(r) for r in raw],
                   key=lambda c: c.get('cvss_score') or 0, reverse=True)
    time.sleep(0.4)

    exps = []
    if not args.no_exploitdb:
        if RICH:
            with Progress(SpinnerColumn(), TextColumn('[cyan]{task.description}'), console=console) as p:
                t = p.add_task('Searching Exploit-DB…', total=None)
                exps = edb_search(svc, ver)
        else:
            print('⟳ Searching Exploit-DB…')
            exps = edb_search(svc, ver)

    techs = mitre_map(svc, cves)

    print_cves(cves)
    print_mitre(techs)
    print_exploits(exps)
    if not args.no_chain:
        print_chain(svc, cves)
    print_summary(svc, ver, cves, techs, exps)

    if args.json:
        Path(args.json).write_text(json.dumps({
            'service': svc, 'version': ver,
            'cves': cves, 'mitre_techniques': techs, 'exploits': exps,
        }, indent=2))
        console.print(f'[green]✓ JSON saved → {args.json}[/green]')

    if args.report:
        html = html_report(svc, ver, cves, techs, exps)
        fname = f"vulnmap_{svc}_{ver or 'any'}_{datetime.now():%Y%m%d_%H%M%S}.html"
        Path(fname).write_text(html, encoding='utf-8')
        console.print(f'[green]✓ Report saved → {fname}[/green]')
        try: webbrowser.open(f'file://{Path(fname).resolve()}')
        except: pass

if __name__ == '__main__':
    main()
