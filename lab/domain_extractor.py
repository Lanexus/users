#!/usr/bin/env python3
import sys, os, re, time, json, socket, threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

class C:
    R = '\033[0m'
    B = '\033[1m'
    D = '\033[2m'
    RED = '\033[38;5;196m'
    GREEN = '\033[38;5;46m'
    YELLOW = '\033[38;5;214m'
    ORANGE = '\033[38;5;208m'
    CYAN = '\033[38;5;51m'
    WHITE = '\033[38;5;255m'
    GRAY = '\033[38;5;245m'
    DIM = '\033[2m'

BAD_TLDS = {
    'htm','html','php','asp','aspx','jsp','cgi','py','js','css','json',
    'xml','txt','log','ini','cfg','conf','env','sh','bat','cmd','exe',
    'dll','so','jpg','jpeg','png','gif','svg','ico','bmp','mp3','mp4',
    'avi','mkv','mov','wmv','pdf','doc','docx','xls','xlsx','ppt',
    'pptx','zip','rar','7z','tar','gz','bz2','db','sqlite','sql',
    'bak','old','tmp','cache','lock'
}

SKIP_HOSTS = {
    'localhost','127.0.0.1','0.0.0.0','::1',
    'example.com','example.org','example.net'
}

PRIVATE_IP = ['10.','172.16.','172.17.','172.18.','172.19.','172.20.',
    '172.21.','172.22.','172.23.','172.24.','172.25.','172.26.',
    '172.27.','172.28.','172.29.','172.30.','172.31.','192.168.','169.254.']

def is_ip(h):
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', h))

def is_private(h):
    return any(h.startswith(p) for p in PRIVATE_IP)

def valid_domain(h):
    if not h or len(h)<4 or is_ip(h) or h.lower() in SKIP_HOSTS or is_private(h):
        return False
    if '.' not in h:
        return False
    parts = h.split('.')
    if len(parts)<2:
        return False
    tld = parts[-1].lower()
    if tld in BAD_TLDS or not re.match(r'^[a-z]{2,12}$', tld):
        return False
    for p in parts:
        if not p or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$', p):
            return False
    return True

def extract_domain(line):
    if not line or not line.strip():
        return None
    line = line.strip()
    parts = line.split(':')
    if len(parts) < 2:
        return None
    raw = parts[0].strip()
    if raw.startswith('http://') or raw.startswith('https://'):
        try:
            h = urlparse(raw).hostname
            if h: return h.lower()
        except: pass
    if raw.startswith('//'):
        h = raw[2:].split('/')[0].split(':')[0]
        return h.lower() if h else None
    h = raw.split('/')[0].split(':')[0].split('?')[0].split('#')[0]
    if h and valid_domain(h):
        return h.lower()
    return None

def banner():
    print(f'''{C.CYAN}{C.B}
  CVE Scanner - Domain Extractor v1.0
  Extract domains from credential files
{C.R}''')

def show_progress(processed, domains, skipped, dupes, start):
    elapsed = time.time() - start
    rate = processed / elapsed if elapsed > 0 else 0
    print(f'\r{C.GRAY}[{time.strftime("%H:%M:%S")}]{C.R} '
          f'{C.CYAN}Lines: {processed:,}{C.R} '
          f'{C.GREEN}Domains: {len(domains):,}{C.R} '
          f'{C.YELLOW}Skipped: {skipped:,}{C.R} '
          f'{C.DIM}{dupes:,} dupes | {rate:.0f}/s{C.R}    ', end='', flush=True)

def process_file(input_file, output_file):
    print(f'{C.CYAN}[*] Input: {input_file}{C.R}')
    print(f'{C.CYAN}[*] Output: {output_file}{C.R}')
    print()

    domains = set()
    processed = 0
    skipped = 0
    dupes = 0
    start = time.time()

    with open(input_file, 'r', errors='ignore') as f:
        for line in f:
            processed += 1
            d = extract_domain(line)
            if d:
                if d in domains:
                    dupes += 1
                else:
                    domains.add(d)
            else:
                skipped += 1
            if processed % 100000 == 0:
                show_progress(processed, domains, skipped, dupes, start)

    show_progress(processed, domains, skipped, dupes, start)
    print()

    with open(output_file, 'w') as f:
        for d in sorted(domains):
            f.write(d + '\n')

    elapsed = time.time() - start
    print(f'{C.CYAN}{"="*50}{C.R}')
    print(f'{C.WHITE}Summary:{C.R}')
    print(f'  Total lines: {processed:,}')
    print(f'  {C.GREEN}Unique domains: {len(domains):,}{C.R}')
    print(f'  {C.YELLOW}Skipped: {skipped:,}{C.R}')
    print(f'  {C.DIM}Duplicates: {dupes:,}{C.R}')
    print(f'  Duration: {elapsed:.1f}s')
    print(f'  Output: {output_file}')
    print(f'{C.CYAN}{"="*50}{C.R}')
    return domains

def check_alive(domains_file, output_file, threads=50, timeout=3):
    print(f'{C.CYAN}[*] Loading domains...{C.R}')
    with open(domains_file) as f:
        domains = [l.strip() for l in f if l.strip()]
    total = len(domains)
    print(f'{C.CYAN}[*] Checking {total:,} domains ({threads} threads)...{C.R}')
    print()

    alive = []
    dead = []
    checked = [0]
    lock = threading.Lock()
    start = time.time()

    def check_domain(domain):
        try:
            socket.getaddrinfo(domain, None)
        except:
            with lock:
                dead.append(domain)
                checked[0] += 1
            return
        for port in [443, 80]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((domain, port))
                s.close()
                with lock:
                    alive.append(domain)
                    checked[0] += 1
                return
            except:
                continue
        with lock:
            dead.append(domain)
            checked[0] += 1

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_domain, d): d for d in domains}
        for f in as_completed(futures):
            c = checked[0]
            elapsed = time.time() - start
            rate = c / elapsed if elapsed > 0 else 0
            pct = (c / total * 100) if total > 0 else 0
            print(f'\r{C.GRAY}[{time.strftime("%H:%M:%S")}]{C.R} '
                  f'{C.CYAN}{pct:.1f}%{C.R} '
                  f'{C.GREEN}Alive: {len(alive):,}{C.R} '
                  f'{C.RED}Dead: {len(dead):,}{C.R} '
                  f'{C.DIM}{rate:.0f}/s{C.R}    ', end='', flush=True)

    print()
    with open(output_file, 'w') as f:
        for d in sorted(alive):
            f.write(d + '\n')

    elapsed = time.time() - start
    print(f'{C.CYAN}{"="*50}{C.R}')
    print(f'{C.WHITE}Validation Summary:{C.R}')
    print(f'  Duration: {elapsed:.1f}s')
    print(f'  Checked: {checked[0]:,}')
    print(f'  {C.GREEN}Alive: {len(alive):,}{C.R}')
    print(f'  {C.RED}Dead: {len(dead):,}{C.R}')
    print(f'  Output: {output_file}')
    print(f'{C.CYAN}{"="*50}{C.R}')

if __name__ == '__main__':
    import argparse
    banner()
    p = argparse.ArgumentParser(description='Extract domains from credential files')
    p.add_argument('-i', '--input', required=True, help='Input file')
    p.add_argument('-o', '--output', help='Output file')
    p.add_argument('-v', '--validate', action='store_true', help='Validate alive')
    p.add_argument('-t', '--threads', type=int, default=50)
    p.add_argument('--timeout', type=int, default=3)
    args = p.parse_args()

    if not os.path.exists(args.input):
        print(f'{C.RED}[!] File not found: {args.input}{C.R}')
        sys.exit(1)

    output = args.output or args.input.rsplit('.', 1)[0] + '_domains.txt'
    process_file(args.input, output)

    if args.validate:
        print()
        alive_output = output.rsplit('.', 1)[0] + '_alive.txt'
        check_alive(output, alive_output, threads=args.threads, timeout=args.timeout)

    print(f'\n{C.GREEN}[+] Done!{C.R}')
