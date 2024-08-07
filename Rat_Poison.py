import psutil
import pefile
import os
from OpenSSL import crypto
import certifi
from tqdm import tqdm
import ipaddress
import requests

def is_signed(file_path):
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            for security_entry in pe.DIRECTORY_ENTRY_SECURITY:
                security_data = security_entry.struct
                certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, pe.write()[security_data.VirtualAddress + 8: security_data.VirtualAddress + security_data.Size])
                store = crypto.X509Store()
                store.set_default_paths()
                store.load_locations(certifi.where())
                store_context = crypto.X509StoreContext(store, certificate)
                store_context.verify_certificate()
                return True
    except:
        return False
    return False

def get_parent_process(pid):
    try:
        parent = psutil.Process(pid).parent()
        if parent:
            return parent
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    return None

def is_external_ip(ip):
    try:
        ip = ipaddress.ip_address(ip)
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        return False

def get_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            return response.json()
    except requests.RequestException:
        return None
    return None

def find_suspicious_connections():
    connections = psutil.net_connections(kind='inet')
    suspicious_connections = []

    for conn in tqdm(connections, desc="Scanning connections", unit="connection"):
        if conn.status == 'ESTABLISHED' and conn.raddr:
            remote_ip = conn.raddr.ip
            if is_external_ip(remote_ip):
                try:
                    process = psutil.Process(conn.pid)
                    parent_process = get_parent_process(conn.pid)
                    if parent_process and parent_process.exe():
                        if not is_signed(parent_process.exe()):
                            geolocation = get_geolocation(remote_ip)
                            if geolocation and "org" in geolocation and "Microsoft" not in geolocation["org"]:
                                suspicious_connections.append((conn, parent_process, geolocation))
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    continue

    return suspicious_connections

def main():
    suspicious_connections = find_suspicious_connections()
    if not suspicious_connections:
        print("Nothing suspicious detected.")
    else:
        for conn, parent, geo in suspicious_connections:
            remote_ip = conn.raddr.ip
            location = geo.get("city", "Unknown") + ", " + geo.get("region", "Unknown") + ", " + geo.get("country", "Unknown")
            org = geo.get("org", "Unknown")
            if "Microsoft" not in org:
                print(f"Suspicious: {parent.name()} - {parent.pid} - Connected to: {remote_ip} - Location: {location} - ISP: {org}")

if __name__ == "__main__":
    main()
