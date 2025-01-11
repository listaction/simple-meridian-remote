#!/usr/bin/env python3

import tkinter as tk
import socket
import netifaces
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

PORT = 9014
TIMEOUT = 0.2  # seconds per connection attempt
MAX_WORKERS = 100  # Adjust as needed

def get_private_subnets():
    """
    Returns a list of ipaddress.ip_network objects corresponding to
    local interfaces that are:
      1) Not loopback by interface name or IP,
      2) Have valid IPv4 addresses in private ranges 
         (10.x, 192.168.x, 172.16–172.31).
    """
    private_subnets = []
    for interface in netifaces.interfaces():
        # Skip loopback interface by name
        if interface.lower() == 'lo':
            continue

        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET not in addrs:
            continue

        for addr_info in addrs[netifaces.AF_INET]:
            ip = addr_info.get('addr')
            netmask = addr_info.get('netmask')
            if not ip or not netmask:
                continue

            # Also skip if this IP is in the 127.0.0.0/8 loopback range
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
            except ValueError:
                continue

            # Convert to ipaddress objects
            try:
                network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
            except ValueError:
                continue

            # We only care if the IP is in a private subnet
            if network.network_address.is_private:
                print(f"[INFO] Found private network: {network} on interface '{interface}'")
                private_subnets.append(network)
    return private_subnets

def check_host_port(ip_str, port=PORT, timeout=TIMEOUT):
    """
    Attempts to connect to 'ip_str' on 'port'.
    Returns ip_str if successful, else None.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((ip_str, port))
            s.close()
            print(f"[INFO] Found listening host: {ip_str}:{port}")
            return ip_str
        except:
            return None

def find_host_listening_on_port(subnet, port=PORT, timeout=TIMEOUT):
    """
    Scans the given 'subnet' (ipaddress.ip_network) using multiple threads
    to find the first host that is listening on 'port'.
    Returns the IP string or None if not found.
    """
    hosts = list(subnet.hosts())
    if not hosts:
        return None

    # Use a ThreadPoolExecutor so we can scan multiple hosts in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {
            executor.submit(check_host_port, str(host), port, timeout): str(host)
            for host in hosts
        }
        # as_completed() yields futures as they complete
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                # We found a host that is listening
                # Cancel remaining tasks & return immediately
                executor.shutdown(wait=False, cancel_futures=True)
                return result
    return None

def auto_discover_meridian_ip():
    """
    Attempts to discover which IP on the system’s private subnets
    is listening on PORT. Returns the first discovered IP or None.
    """
    private_subnets = get_private_subnets()
    if not private_subnets:
        print("[WARN] No private subnets found.")
        return None

    # Scan each private subnet until we find a listening IP
    for subnet in private_subnets:
        print(f"[INFO] Scanning subnet {subnet} for hosts on port {PORT}...")
        host_ip = find_host_listening_on_port(subnet, port=PORT, timeout=TIMEOUT)
        if host_ip:
            return host_ip

    print("[WARN] No Meridian device found on any scanned private subnet.")
    return None

def send_command(command, host, port=PORT):
    """
    Opens a TCP connection to `host:port`, sends `command`, then closes.
    Meridian typically requires a carriage return (\r).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(command.encode('utf-8'))
        print(f"[INFO] Sent command: {command!r} to {host}:{port}")
    except Exception as e:
        print(f"[ERROR] Error sending command to {host}:{port}: {e}")

def main():
    print("[INFO] Attempting to discover Meridian device on local private subnets...")

    # This call is synchronous: it won't return until the scan completes
    discovered_ip = auto_discover_meridian_ip()

    # If not found, we just end (or you could default to something else)
    if not discovered_ip:
        print("[ERROR] Could not find a Meridian device listening on port 9014.")
        return

    print(f"[INFO] Using Meridian at {discovered_ip}:{PORT}")
    
    # Build the GUI
    root = tk.Tk()
    root.title("Meridian Control")

    frame = tk.Frame(root, padx=20, pady=20)
    frame.pack()

    tk.Button(
        frame,
        text="Volume Up",
        command=lambda: send_command("#MSR VP\r", host=discovered_ip)
    ).pack(pady=5)

    tk.Button(
        frame,
        text="Volume Down",
        command=lambda: send_command("#MSR VM\r", host=discovered_ip)
    ).pack(pady=5)

    tk.Button(
        frame,
        text="Mute",
        command=lambda: send_command("#MSR MV\r", host=discovered_ip)
    ).pack(pady=5)

    tk.Button(
        frame,
        text="Unmute",
        command=lambda: send_command("#MSR DM\r", host=discovered_ip)
    ).pack(pady=5)

    # Finally, run the Tkinter main loop so the program stays alive
    root.mainloop()

if __name__ == "__main__":
    main()

