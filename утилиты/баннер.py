#!/usr/bin/env python3

from colorama import Fore, Style, Back
import time
import random
import sys
import os

def clear_screen():
    """Очищает экран"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_with_typing_effect(text, delay=0.001):
    """Печатает текст с эффектом печатной машинки"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def print_banner(tool_name):
    clear_screen()
    banner_text = f"""
{Fore.CYAN}
██╗   ██╗███████╗ ██╗██████╗ ███████╗ █████╗ 
██║   ██║██╔════╝███║╚════██╗╚════██║██╔══██╗
██║   ██║███████╗╚██║ █████╔╝    ██╔╝███████║
██║   ██║╚════██║ ██║ ╚═══██╗   ██╔╝ ██╔══██║
╚██████╔╝███████║ ██║██████╔╝   ██║  ██║  ██║
 ╚═════╝ ╚══════╝ ╚═╝╚═════╝    ╚═╝  ╚═╝  ╚═╝
{Style.RESET_ALL}"""
    
    print(banner_text)
    
    info_text = f"""
{Back.RED}{Fore.WHITE} Инструменты кибербезопасности - {tool_name} {Style.RESET_ALL}
{Fore.YELLOW}[*] Автор: US1BZA{Style.RESET_ALL}
{Fore.BLUE}[*] Версия: 2.0{Style.RESET_ALL}
{Fore.BLUE}[*] GitHub: https://github.com/US1BZA{Style.RESET_ALL}
{Fore.RED}[!] Только для образовательных целей. Ответственность за неправомерное использование лежит на пользователе.{Style.RESET_ALL}
"""
    print_with_typing_effect(info_text)
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

def print_tool_info(description, features):
    """Выводит информацию об инструменте"""
    print(f"\n{Fore.YELLOW}[*] Описание:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{description}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}[*] Возможности:{Style.RESET_ALL}")
    for feature in features:
        print(f"{Fore.GREEN}[+] {feature}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

def print_status(message, status="info"):
    """Выводит сообщения о состоянии"""
    status_colors = {
        "info": Fore.BLUE,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error": Fore.RED
    }
    color = status_colors.get(status, Fore.WHITE)
    print(f"{color}[{status.upper()}] {message}{Style.RESET_ALL}")
