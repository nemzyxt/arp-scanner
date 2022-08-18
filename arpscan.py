# Author : Nemuel Wainaina

from colorama import init, Fore
from scapy.all import ARP, Ether, srp

import os

init()
GREEN = Fore.GREEN
RED = Fore.RED
GRAY = Fore.LIGHTBLACK_EX
RESET = Fore.RESET

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}[!] The script requires root privileges to run {RESET}")
        exit(1)

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", dest="interface", help="Network Interface to scan on", required=True)
    parser.add_argument("-r", "--range", dest="ip_range", help="IP Range to scan for hosts", required=True)
    parser.add_argument("-t", "--timeout", dest="timeout", help="Timeout on a host")

    args = parser.parse_args()
    iface = args.interface
    ip_range = args.ip_range
    timeout = 2 # default
    if args.timeout and int(args.timeout) > 0:
        timeout = int(args.timeout)

    broadcast = "FF:FF:FF:FF:FF:FF"
    ether_layer = Ether(dst=broadcast)
    arp_layer = ARP(pdst=ip_range)

    packet = ether_layer / arp_layer

    ans, unans = srp(packet, iface=iface, timeout=timeout)

    hosts = 0

    print()
    for snd, rcv in ans:
        hosts += 1
        ip = rcv[ARP].psrc
        mac = rcv[Ether].src
        print(f"[*] {ip} :: {mac}")

    print("Done !")

    if hosts == 0:
        print(f"{GRAY}[-] No hosts found :( {RESET}")
    else:
        print(f"{GREEN}[+] Found {hosts} hosts :) {RESET}")

