from scapy.all import  sniff, DNS, DNSQR, IP
import sys
import logging
from datetime import datetime
import math
from collections import Counter
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import requests
from colorama import Fore,Style,init
import os
import threading
import time

import argparse
#---------------------------- ------------- ---------------- ---------------- ------------- -------------
init(autoreset=True)

TRUSTED_DOMAINS = []
MALICIOUS_DB = set()
spam_queries = set()


Known_Good_Domains=[
     "google.com",
    "gstatic.com",
    "googleapis.com",
    "microsoft.com",
    "microsoftonline.com",
    "windows.net",
    "cloudflare.com",
    "github.com",
    "githubusercontent.com",
    "amazonaws.com"
]

def print_banner():
    print(f"\n{Fore.RED}{Style.BRIGHT}[+] Passive DNS Threat Monitor v1.0.0{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] Created by: x3bdulaziz (github.com/x3bdulaziz)\n")
def is_known_good(domain):
    domain = domain.lower()
    return any(domain==d or domain.endswith("."+d) for d in Known_Good_Domains )


def calculate_risk_score(domain,subdomain,entropy_value):

    score = 0
    domain = domain.lower()
    #high malicious score 100 from OSINT
    if is_known_good(domain):
        return 0
    
    domain_parts = domain.split(".")
    for i in range(len(domain_parts)):
       presnt_domain = ".".join(domain_parts[i:])
       if presnt_domain in MALICIOUS_DB:
           return 100
    if domain in MALICIOUS_DB:
        return 100

    if entropy_value > 4.2:
        score += 40
    
    elif entropy_value > 3.8:
        score += 20
    if len(subdomain) >12:
        score += 15
    
    total_score_risk = domain.split(".")[-1]
    risk_tsr = ["xyz","top","shop","click","online"]
    if total_score_risk in risk_tsr:
        score += 20
    return min(score,100)



def entropy(text):
    if not text:
        return 0
    
    counter = Counter(text)
    total = len(text)

    entropy_value = 0
    for count in counter.values():
        p = count / total
        entropy_value -= p * math.log2(p)
    return entropy_value


def Load_configuration():
    global TRUSTED_DOMAINS , MALICIOUS_DB
    try:
        with open("trust.txt","r") as t:
            TRUSTED_DOMAINS = [line.strip() for line in t if line.strip()]


    except FileNotFoundError:
        with open("trust.txt","w") as t:
            t.write("mozilla.org")
            TRUSTED_DOMAINS =["mozilla.org"]
    try:
        with open("blacklist.txt","r") as b:
            for line in b:
                if line.strip():
                    MALICIOUS_DB.add(line.strip().lower())
    except FileNotFoundError:
        with open("blacklist.txt","w") as b:
            b.write("")




def update_threat_intel():#Open Source Intelligence 
    global MALICIOUS_DB
    threat_feeds = ["https://urlhaus.abuse.ch/downloads/hostfile/",
                    "https://threatfox.abuse.ch/downloads/hostfile/",
                    "https://openphish.com/feed.txt",
                    "https://bazaar.abuse.ch/export/txt/urls/recent/"
                    ]
    print("updating: Open-Source Intelligence(OSINT) please wait... ")
    for feeds in threat_feeds:
        try:
            
            response = requests.get(url=feeds,timeout=(5,15))

            if response.status_code != 200:
                    continue
            
            
            for line in response.text.splitlines():
                line = line.strip()        
                
                if not line or line.startswith("#"):
                    continue
                
                parts = line.split()
                if len(parts) <1:
                    continue
                domain = parts[-1].lower()
                
                if "://" in domain:
                    domain = domain.split("://")[1].split("/")[0]
                elif "/" in domain:
                    domain = domain.split("/")[0]
                if "." not in domain:
                    continue
                MALICIOUS_DB.add(domain.lower())

        except requests.RequestException as e:
            print(f"[network/ssl error]:: skipping feeds: {e}")
            
            
        except Exception as e:
            print(f"[Feeds failed]:: {feeds} ->{e}")
            
    

def is_trusted(domain):
    
    domain = domain.lower()
    return any(domain == t or domain.endswith("."+t) for t in TRUSTED_DOMAINS)    

    

def analyze_dns_packet(packet):
    
    try:
        if packet.haslayer(DNS) and packet[DNS].qr ==0:
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                dns_query = packet[DNSQR].qname.decode(errors="ignore").strip(".")
                
                
                
                current_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

                
                if not dns_query or is_trusted(dns_query) or  dns_query in spam_queries:
                    return
                if len(spam_queries) > 5000:
                    spam_queries.clear()
                
                spam_queries.add(dns_query)  
                subdomain = dns_query.split(".")[0]
                entropy_value = entropy(subdomain)
                
                risk_score = calculate_risk_score(dns_query,subdomain , entropy_value)

                status_safe = f"{current_time} [SAFE {risk_score}]"
                status_warn = f"{current_time} [SUSPICIOUS {risk_score}]"
                status_crit = f"{current_time} [Critical {risk_score}]"
                if risk_score <20 :
                   print(f" {status_safe:<38}{ip_src:<18}{dns_query:<45}[reason: Normal Traffic ]")
                
                elif risk_score < 60:
                    warn_msg = f"{status_warn:<38}{ip_src:<18}{dns_query:<45}[reason:High entropy domain]"
                    print(f"{Fore.YELLOW}{Style.BRIGHT}{warn_msg}")                    
                    log_to_file(warn_msg)

                else:
                    Critical_alerts=(f"{status_crit:<38}{ip_src:<18}{dns_query:<45}[reason: found in threat intelligence feeds]")
                    print(f"{Fore.RED}{Style.BRIGHT}{Critical_alerts}")
                    log_to_file(Critical_alerts)


                
  
                    
    except Exception as e:
        print(f"error analyze_dns_packet(packet): {e}")
       



 
    
def log_to_file(message):
    current_time_file = datetime.now().strftime("%d-%m-%Y") 
    try:
        with open(f"dns_detection_{current_time_file}.log",'a') as f:
            f.write(message+"\n")
    except Exception as e:print(f"error: log_to_file() {e}")


 

def start_monitor(interface):
    Load_configuration()
    update_threat_intel()
    current_time = datetime.now().strftime("%d-%m-%Y") 
    print("==================================================================================================================================")
    print("[&] Passive DNS threat monitor  system Enabled.")
    print(f"#Note Alerts will be saved automatically to [ dns_detection_{current_time}.log ] ")
    print("==================================================================================================================================")
    print(f"{'STATUS':<38} {'SOURCE IP':<17}{'REQUESTED DOMAIN':<45}  {'ANALYSIS/REASON'}")
    print("---------------------------------------------------------------------------------------------------------------------------------")

   
    sniff_thread =threading.Thread(target=lambda:sniff(iface=interface,filter="udp port 53",prn=analyze_dns_packet,store=0),
            daemon=True                              
                                  )
    sniff_thread.start()
    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
            print("\nStoping Monitor DNS traffic.. all alerts were saved successfuly")
            os._exit(0)
                
    except Exception as e:
            print(f"error start_montor(): {e}")
            
            

    


if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="DNS Threat Monitor by x3bdulaziz")
    parser.add_argument("-i","--interface",help="Network interface to sniff on (e.g,eth0,wlan0)",default=None)
    args = parser.parse_args()
    start_monitor(interface=args.interface)

