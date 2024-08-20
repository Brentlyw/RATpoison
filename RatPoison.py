import psutil
import ipaddress
import logging
import time
import os
import pefile
import math
import hashlib
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn
import socket
import re
import signify.authenticode
import logging
logging.basicConfig(filename='RatPoison.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
console = Console()
def isextip(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
def issigned(filepath):
    try:
        with open(filepath, "rb") as f:
            pefile = signify.authenticode.SignedPEFile(f)
            if pefile.signed_datas:
                for signed_data in pefile.signed_datas:
                    signer_info = signed_data.signer_info.program_name
                    logging.info(f"File {filepath} is signed by {signer_info}.")
                    if signed_data.signer_info.countersigner is not None:
                        signing_time = signed_data.signer_info.countersigner.signing_time
                        logging.info(f"Signing time: {signing_time}")
                return True
            else:
                logging.warning(f"File {filepath} is not signed.")
                return False

    except Exception as e:
        logging.warning(f"Error checking signature for {filepath}: {e}")
        return False

def calcentropy(data):
    if not data:
        return 0.0
    return -sum((data.count(x) / len(data)) * math.log2(data.count(x) / len(data)) for x in range(256) if data.count(x))
def largestsectentropy(fp):
    try:
        pe = pefile.PE(fp)
        sects = [s for s in pe.sections if s.Characteristics & 0x20000000]
        if not sects:
            return 0.0
        return calcentropy(max(sects, key=lambda s: s.SizeOfRawData).get_data())
    except Exception as e:
        logging.warning(f"Error calculating entropy for {fp}: {e}")
        return 0
def isddns(domain):
    patterns = [r'\.dyndns\.org$', r'\.no-ip\.com$', r'\.ddns\.net$', r'\.hopto\.org$', r'\.serveo\.net$', r'\.ngrok\.io$']
    return any(re.search(pat, domain.lower()) for pat in patterns)
def longconn(conn):
    try:
        return (time.time() - psutil.Process(conn.pid).create_time()) > 3600
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
def nonstdport(port, svc):
    stdports = {
        'http': [80, 443], 'https': [80, 443], 'dns': [80, 53, 443],
        'ftp': [21], 'ssh': [22], 'telnet': [23], 'smtp': [25],
        'pop3': [110], 'imap': [143], 'rdp': [3389]
    }
    return port not in stdports.get(svc.lower(), [])
def issusploc(path):
    locs = [r'\\temp\\', r'\\appdata\\', r'\\startup\\', r'\\programdata\\', r'\\users\\public\\']
    return any(loc in path.lower() for loc in locs)
def hasargs(cmd):
    args = ['-hidden', '-nowindow', '-silent', '-background',
            '/hidden', '/nowindow', '/silent', '/background',
            '--hidden', '--nowindow', '--silent', '--background']
    return any(arg.lower() in cmd for arg in args)
def chkconn(conn):
    if conn.status != 'ESTABLISHED' or not conn.raddr or not isextip(conn.raddr.ip):
        return None
    try:
        proc = psutil.Process(conn.pid).parent() or psutil.Process(conn.pid)
        reasons = []
        if not issigned(proc.exe()):
            reasons.append("Unsigned executable")
        ent = largestsectentropy(proc.exe())
        if ent > 7.0:
            reasons.append(f"High entropy: {ent:.2f}")
        if conn.raddr.port in {20, 21, 22, 23, 25, 3389, 5900} or conn.raddr.port > 49151:
            reasons.append(f"Suspicious port: {conn.raddr.port}")
        if hasargs(proc.cmdline()):
            reasons.append("Suspicious args")
        if issusploc(proc.exe()):
            reasons.append(f"Suspicious location: {proc.exe()}")
        try:
            domain = socket.gethostbyaddr(conn.raddr.ip)[0]
            if isddns(domain):
                reasons.append(f"DDNS: {domain}")
        except socket.herror:
            pass
        if longconn(conn):
            reasons.append("Long duration")
        for svc in ['http', 'https', 'dns']:
            if nonstdport(conn.raddr.port, svc):
                reasons.append(f"Non-standard port for {svc.upper()}: {conn.raddr.port}")
        if len(reasons) >= 2:
            return (conn, proc, reasons, issigned(proc.exe()), ent)
    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as e:
        logging.warning(f"Error processing {conn}: {e}")
    return None
def analyze():
    conns = psutil.net_connections(kind='inet')
    susconns = []
    with Progress("[progress.description]{task.description}", BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%") as progress:
        task = progress.add_task("[cyan]Analyzing..", total=len(conns))
        for conn in conns:
            result = chkconn(conn)
            if result:
                susconns.append(result)
            progress.update(task, advance=1)
    return susconns
def printconn(conn, proc, reasons, signed, ent):
    table = Table(show_header=False, box=None)
    table.add_row("[bold yellow]Process:", f"{proc.name()} (PID: {proc.pid})")
    table.add_row("[bold yellow]Connection:", f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
    table.add_row("[bold yellow]Executable:", proc.exe())
    table.add_row("[bold yellow]Signed:", "Yes" if signed else "No")
    table.add_row("[bold yellow]Entropy:", f"{ent:.2f}")
    table.add_row("[bold yellow]Reasons:", "\n".join(f"• {r}" for r in reasons))
    try:
        with open(proc.exe(), "rb") as f:
            table.add_row("[bold yellow]SHA256 Hash:", hashlib.sha256(f.read()).hexdigest())
    except Exception as e:
        logging.error(f"Error hashing file: {e}")
    console.print(Panel(table, title="[bold red]Suspicious Connection", expand=False))
def main():
    console.print(Panel.fit("[bold green]RAT Poison - Version 1.1", border_style="green"))
    start = time.time()
    susconns = analyze()
    end = time.time()
    if not susconns:
        console.print(Panel("[bold green]No suspicious connections found. :-)", border_style="green"))
    else:
        console.print(f"\n[bold yellow]Found {len(susconns)} suspicious connections:")
        for conn_data in susconns:
            printconn(*conn_data)
    console.print(f"\n[cyan]RatPoison completed in {end - start:.2f} seconds. Check 'RatPoison.log' for details.")
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
