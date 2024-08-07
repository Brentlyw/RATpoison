import psutil
import pefile
import os
from OpenSSL import crypto
import certifi
from tqdm import tqdm
import ipaddress
import requests
import math

def issigned(filepath):
    try:
        pe = pefile.PE(filepath)
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            for sec in pe.DIRECTORY_ENTRY_SECURITY:
                secdata = sec.struct
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, pe.write()[secdata.VirtualAddress + 8: secdata.VirtualAddress + secdata.Size])
                store = crypto.X509Store()
                store.set_default_paths()
                store.load_locations(certifi.where())
                storectx = crypto.X509StoreContext(store, cert)
                storectx.verify_certificate()
                return True
    except:
        return False
    return False

def calculate_entropy(filepath):
    with open(filepath, 'rb') as f:
        byte_arr = list(f.read())
    file_size = len(byte_arr)
    freq_list = []
    
    for b in range(256):
        ctr = byte_arr.count(b)
        freq_list.append(float(ctr) / file_size)
    
    entropy = 0.0
    for freq in freq_list:
        if freq > 0:
            entropy = entropy + freq * math.log2(freq)
    entropy = -entropy
    return entropy

def getparentproc(pid):
    try:
        parent = psutil.Process(pid).parent()
        if parent:
            return parent
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    return None

def isexternalip(ip):
    try:
        ip = ipaddress.ip_address(ip)
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        return False

def getgeo(ip):
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json")
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        return None
    return None

def findsuspconns():
    conns = psutil.net_connections(kind='inet')
    suspconns = []

    for conn in tqdm(conns, desc="Checking connections..", unit="connection"):
        if conn.status == 'ESTABLISHED' and conn.raddr:
            raddr = conn.raddr.ip
            if isexternalip(raddr):
                try:
                    proc = psutil.Process(conn.pid)
                    parentproc = getparentproc(conn.pid)
                    if parentproc and parentproc.exe():
                        signed = issigned(parentproc.exe())
                        entropy = calculate_entropy(parentproc.exe())
                        if not signed or entropy > 7.0:
                            geo = getgeo(raddr)
                            if geo and "org" in geo and not any(x in geo["org"] for x in ["Microsoft", "Akamai", "Cloudflare"]):
                                suspconns.append((conn, parentproc, geo))
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    continue

    return suspconns

def main():
    suspconns = findsuspconns()
    if not suspconns:
        print("Nothing suspicious found.")
    else:
        for conn, parent, geo in suspconns:
            raddr = conn.raddr.ip
            loc = geo.get("city", "Unknown") + ", " + geo.get("region", "Unknown") + ", " + geo.get("country", "Unknown")
            org = geo.get("org", "Unknown")
            print(f"Suspicious: {parent.name()} - {parent.pid} - Connected to: {raddr} - Location: {loc} - ISP: {org} - State/Country: {geo.get('region', 'Unknown')}/{geo.get('country', 'Unknown')}")

if __name__ == "__main__":
    main()
