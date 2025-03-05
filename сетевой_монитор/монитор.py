#!/usr/bin/env python3

from scapy.all import *
from colorama import init, Fore, Style
import argparse
from datetime import datetime
import signal
import sys
import os
import time
from tqdm import tqdm
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from утилиты.баннер import print_banner, print_tool_info, print_status

init()

packet_counts = {
    'TCP': {'total': 0, 'ports': {}},
    'UDP': {'total': 0, 'ports': {}},
    'ICMP': {'total': 0, 'types': {}},
    'DNS': {'total': 0, 'queries': {}},
    'HTTP': {'total': 0, 'methods': {}},
    'Other': {'total': 0},
    'Total': 0
}

start_time = None
captured_ips = set()
suspicious_activities = []

def signal_handler(sig, frame):
    end_time = datetime.now()
    duration = end_time - start_time
    
    print(f"\n{Fore.CYAN}=== Статистика ==={Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Время мониторинга: {duration}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Всего пакетов: {packet_counts['Total']}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Уникальных IP: {len(captured_ips)}{Style.RESET_ALL}\n")
    
    print(f"{Fore.CYAN}=== Статистика протоколов ==={Style.RESET_ALL}")
    for proto in ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'Other']:
        if packet_counts[proto]['total'] > 0:
            print(f"\n{Fore.GREEN}[+] {proto}:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}├── Всего: {packet_counts[proto]['total']}{Style.RESET_ALL}")
            
            if proto in ['TCP', 'UDP']:
                print(f"{Fore.GREEN}└── Популярные порты:{Style.RESET_ALL}")
                sorted_ports = sorted(packet_counts[proto]['ports'].items(), 
                                   key=lambda x: x[1], reverse=True)[:5]
                for port, count in sorted_ports:
                    print(f"    └── Порт {port}: {count}")
                    
            elif proto == 'ICMP':
                print(f"{Fore.GREEN}└── Типы ICMP:{Style.RESET_ALL}")
                for icmp_type, count in packet_counts[proto]['types'].items():
                    print(f"    └── Тип {icmp_type}: {count}")
                    
            elif proto == 'DNS':
                print(f"{Fore.GREEN}└── DNS запросы:{Style.RESET_ALL}")
                sorted_queries = sorted(packet_counts[proto]['queries'].items(),
                                     key=lambda x: x[1], reverse=True)[:5]
                for query, count in sorted_queries:
                    print(f"    └── {query}: {count}")
                    
            elif proto == 'HTTP':
                print(f"{Fore.GREEN}└── HTTP методы:{Style.RESET_ALL}")
                for method, count in packet_counts[proto]['methods'].items():
                    print(f"    └── {method}: {count}")
    
    if suspicious_activities:
        print(f"\n{Fore.CYAN}=== Подозрительная активность ==={Style.RESET_ALL}")
        for activity in suspicious_activities:
            print(f"{Fore.RED}[!] {activity}{Style.RESET_ALL}")
    
    sys.exit(0)

def check_suspicious_activity(packet):
    if TCP in packet:
        if packet[TCP].flags & 0x02:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            key = f"{src_ip}:{dst_port}"
            if key not in packet_counts['TCP']:
                packet_counts['TCP'][key] = 0
            packet_counts['TCP'][key] += 1
            
            if packet_counts['TCP'][key] > 100:
                suspicious_activities.append(f"SYN Flood атака: {src_ip} -> Порт {dst_port}")
        
        if packet[TCP].flags & 0x3F == 0:
            suspicious_activities.append(f"NULL сканирование: {packet[IP].src}")
        elif packet[TCP].flags & 0x01:
            suspicious_activities.append(f"FIN сканирование: {packet[IP].src}")
        elif packet[TCP].flags & 0x29:
            suspicious_activities.append(f"XMAS сканирование: {packet[IP].src}")

def analyze_dns_packet(packet):
    if packet.haslayer(DNS):
        packet_counts['DNS']['total'] += 1
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode('utf-8')
            packet_counts['DNS']['queries'][query] = packet_counts['DNS']['queries'].get(query, 0) + 1

def analyze_http_packet(packet):
    if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
        if Raw in packet:
            try:
                data = packet[Raw].load.decode('utf-8')
                if data.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD')):
                    packet_counts['HTTP']['total'] += 1
                    method = data.split()[0]
                    packet_counts['HTTP']['methods'][method] = packet_counts['HTTP']['methods'].get(method, 0) + 1
            except:
                pass

def packet_callback(packet):
    packet_counts['Total'] += 1
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if TCP in packet:
        packet_counts['TCP']['total'] += 1
        protocol = 'TCP'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        packet_counts['TCP']['ports'][src_port] = packet_counts['TCP']['ports'].get(src_port, 0) + 1
        packet_counts['TCP']['ports'][dst_port] = packet_counts['TCP']['ports'].get(dst_port, 0) + 1
        analyze_http_packet(packet)
        check_suspicious_activity(packet)
    elif UDP in packet:
        packet_counts['UDP']['total'] += 1
        protocol = 'UDP'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        packet_counts['UDP']['ports'][src_port] = packet_counts['UDP']['ports'].get(src_port, 0) + 1
        packet_counts['UDP']['ports'][dst_port] = packet_counts['UDP']['ports'].get(dst_port, 0) + 1
        analyze_dns_packet(packet)
    elif ICMP in packet:
        packet_counts['ICMP']['total'] += 1
        protocol = 'ICMP'
        src_port = '-'
        dst_port = '-'
        icmp_type = packet[ICMP].type
        packet_counts['ICMP']['types'][icmp_type] = packet_counts['ICMP']['types'].get(icmp_type, 0) + 1
    else:
        packet_counts['Other']['total'] += 1
        protocol = 'Other'
        src_port = '-'
        dst_port = '-'
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        captured_ips.add(src_ip)
        captured_ips.add(dst_ip)
        
        size = len(packet)
        if size < 64:
            size_color = Fore.GREEN
        elif size < 512:
            size_color = Fore.YELLOW
        else:
            size_color = Fore.RED
            
        print(f"{Fore.BLUE}[{timestamp}] {Fore.GREEN}{protocol:5s} {Style.RESET_ALL}"
              f"│ {src_ip:15s}:{src_port:<5} → {dst_ip:15s}:{dst_port:<5} "
              f"│ {size_color}Size: {size:4d} B{Style.RESET_ALL}")

def start_monitoring(interface=None, bpf_filter=None):
    global start_time
    start_time = datetime.now()
    
    tool_desc = "Продвинутый сетевой монитор"
    tool_features = [
        "Анализ пакетов в реальном времени",
        "Статистика по протоколам",
        "Анализ DNS и HTTP трафика",
        "Обнаружение подозрительной активности",
        "Статистика использования портов",
        "Подробная отчетность"
    ]
    
    print_banner("Network Monitor")
    print_tool_info(tool_desc, tool_features)
    
    print_status(f"Интерфейс: {interface if interface else 'Все'}", "info")
    if bpf_filter:
        print_status(f"BPF фильтр: {bpf_filter}", "info")
    print_status(f"Время запуска: {start_time}", "info")
    print_status("Нажмите Ctrl+C для остановки", "info")
    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        sniff(iface=interface, filter=bpf_filter, prn=packet_callback, store=0)
    except Exception as e:
        print_status(f"Ошибка: {str(e)}", "error")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Сетевой монитор')
    parser.add_argument('-i', '--interface', help='Сетевой интерфейс')
    parser.add_argument('-f', '--filter', help='BPF фильтр (пример: "port 80" или "host 192.168.1.1")')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print_status("Требуются права root", "error")
        sys.exit(1)
        
    start_monitoring(args.interface, args.filter)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nПрограмма остановлена пользователем", "warning")
        sys.exit(0)
