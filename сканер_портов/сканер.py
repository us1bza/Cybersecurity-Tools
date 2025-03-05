#!/usr/bin/env python3

import nmap
import sys
import os
import time
import socket
import ipaddress
from colorama import init, Fore, Style
from datetime import datetime
from tqdm import tqdm
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from утилиты.баннер import print_banner, print_tool_info, print_status

init()

SCAN_TYPES = {
    'SYN': {'args': '-sS -sV -T4', 'desc': 'TCP SYN сканирование'},
    'TCP': {'args': '-sT -sV -T4', 'desc': 'TCP Connect сканирование'},
    'UDP': {'args': '-sU -sV -T4', 'desc': 'UDP сканирование'},
    'ACK': {'args': '-sA -T4', 'desc': 'TCP ACK сканирование'},
    'FIN': {'args': '-sF -T4', 'desc': 'TCP FIN сканирование'},
    'NULL': {'args': '-sN -T4', 'desc': 'TCP NULL сканирование'},
    'XMAS': {'args': '-sX -T4', 'desc': 'TCP XMAS сканирование'},
    'FULL': {'args': '-sS -sU -sV -A -T4', 'desc': 'Полное сканирование'}
}

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port_range(port_range):
    try:
        start, end = map(int, port_range.split('-'))
        return 0 <= start <= end <= 65535
    except:
        return False

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Hostname не найден"

def scan_ports(target_host, port_range, scan_type='SYN'):
    if not validate_ip(target_host):
        print_status(f"Неверный IP адрес: {target_host}", "error")
        return False
        
    if not validate_port_range(port_range):
        print_status(f"Неверный диапазон портов: {port_range}", "error")
        return False
        
    if scan_type not in SCAN_TYPES:
        print_status(f"Неверный тип сканирования: {scan_type}", "error")
        return False

    print_status(f"Цель: {target_host} ({get_hostname(target_host)})", "info")
    print_status(f"Диапазон портов: {port_range}", "info")
    print_status(f"Тип сканирования: {scan_type} - {SCAN_TYPES[scan_type]['desc']}", "info")
    print_status(f"Начало: {str(datetime.now())}", "info")

    nm = nmap.PortScanner()
    
    try:
        start_port, end_port = map(int, port_range.split('-'))
        total_ports = end_port - start_port + 1
        
        with tqdm(total=total_ports, desc="Прогресс сканирования", 
                 bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Fore.RESET)) as pbar:
            def callback_progress(host, remaining):
                pbar.update(1)
            
            nm.scan(target_host, port_range, arguments=SCAN_TYPES[scan_type]['args'], callback=callback_progress)
        
        for host in nm.all_hosts():
            print(f"\n{Fore.CYAN}=== Информация о хосте ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] IP: {host}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Hostname: {nm[host].hostname()}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Статус: {nm[host].state()}{Style.RESET_ALL}")
            
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    print(f"{Fore.GREEN}[+] ОС: {osmatch['name']} ({osmatch['accuracy']}%){Style.RESET_ALL}")
            
            for proto in nm[host].all_protocols():
                print(f"\n{Fore.CYAN}=== {proto.upper()} порты ==={Style.RESET_ALL}")
                
                ports = sorted(nm[host][proto].keys())
                open_ports = 0
                closed_ports = 0
                filtered_ports = 0
                
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port]['version']
                    
                    if state == 'open':
                        open_ports += 1
                        print(f"{Fore.GREEN}[+] Порт: {port:5d} │ Статус: {state:8s} │ Сервис: {service:15s} │ Версия: {version}{Style.RESET_ALL}")
                    elif state == 'filtered':
                        filtered_ports += 1
                        print(f"{Fore.YELLOW}[?] Порт: {port:5d} │ Статус: {state:8s} │ Сервис: {service:15s} │ Версия: {version}{Style.RESET_ALL}")
                    else:
                        closed_ports += 1
                        print(f"{Fore.RED}[-] Порт: {port:5d} │ Статус: {state:8s} │ Сервис: {service:15s} │ Версия: {version}{Style.RESET_ALL}")
                
                print(f"\n{Fore.CYAN}=== Статистика портов ==={Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Открытые порты: {open_ports}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[?] Фильтруемые порты: {filtered_ports}{Style.RESET_ALL}")
                print(f"{Fore.RED}[-] Закрытые порты: {closed_ports}{Style.RESET_ALL}")
                        
    except Exception as e:
        print_status(f"Ошибка: {str(e)}", "error")
        return False
    
    print_status("Сканирование завершено", "success")
    print_status(f"Конец: {str(datetime.now())}", "info")
    return True

def main():
    tool_desc = "Продвинутый сканер портов"
    tool_features = [
        "Множество типов сканирования",
        "Определение сервисов и версий",
        "Определение ОС",
        "Детальный анализ портов",
        "Индикатор прогресса",
        "Цветной вывод"
    ]
    
    print_banner("Port Scanner")
    print_tool_info(tool_desc, tool_features)

    if os.geteuid() != 0:
        print_status("Требуются права root", "error")
        sys.exit(1)

    if len(sys.argv) < 3:
        print_status("Использование: sudo python3 port_scanner.py <цель> <диапазон_портов> [тип_скана]", "info")
        print("\nТипы сканирования:")
        for scan_type, info in SCAN_TYPES.items():
            print(f"{Fore.YELLOW}[*] {scan_type:5s}: {info['desc']}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Пример: sudo python3 port_scanner.py 192.168.1.1 1-1000 SYN{Style.RESET_ALL}")
        sys.exit(1)
        
    target = sys.argv[1]
    ports = sys.argv[2]
    scan_type = sys.argv[3] if len(sys.argv) > 3 else 'SYN'
    
    scan_ports(target, ports, scan_type)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nСканирование прервано пользователем", "warning")
        sys.exit(0)
