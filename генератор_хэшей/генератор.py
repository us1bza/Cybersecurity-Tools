#!/usr/bin/env python3

import hashlib
import argparse
import os
import sys
import time
from colorama import init, Fore, Style
from tqdm import tqdm
import requests
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from утилиты.баннер import print_banner, print_tool_info, print_status

init()

CHUNK_SIZE = 8192
SUPPORTED_ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
    'sha3_256': hashlib.sha3_256,
    'sha3_512': hashlib.sha3_512,
    'blake2b': hashlib.blake2b,
    'blake2s': hashlib.blake2s
}

def get_file_size(file_path):
    try:
        return os.path.getsize(file_path)
    except:
        return 0

def check_hash_breach(hash_value):
    try:
        prefix = hash_value[:5]
        suffix = hash_value[5:].upper()
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)
        
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
        return 0
    except:
        return -1

def generate_hash(data, algorithm='sha256'):
    try:
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"Неподдерживаемый алгоритм: {algorithm}")
            
        hash_obj = SUPPORTED_ALGORITHMS[algorithm]()
        
        if os.path.isfile(data):
            file_size = get_file_size(data)
            with open(data, 'rb') as f:
                with tqdm(total=file_size, unit='B', unit_scale=True, 
                         desc=f"Генерация {algorithm.upper()} хэша",
                         bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Fore.RESET)) as pbar:
                    for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                        hash_obj.update(chunk)
                        pbar.update(len(chunk))
        else:
            print_status("Генерация хэша текста...", "info")
            hash_obj.update(data.encode())
            
        return hash_obj.hexdigest()
        
    except Exception as e:
        print_status(f"Ошибка: {str(e)}", "error")
        return None

def verify_hash(data, hash_value, algorithm='sha256'):
    print_status("Проверка хэша...", "info")
    generated_hash = generate_hash(data, algorithm)
    if generated_hash:
        return generated_hash.lower() == hash_value.lower()
    return False

def print_hash_info(algorithm, hash_value, data_type="text"):
    print(f"\n{Fore.CYAN}=== Информация о хэше ==={Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Алгоритм: {algorithm.upper()}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Тип данных: {data_type.capitalize()}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Длина хэша: {len(hash_value)} символов{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Значение хэша: {hash_value}{Style.RESET_ALL}")
    
    if algorithm in ['sha1', 'md5']:
        print(f"\n{Fore.RED}[!] Внимание: {algorithm.upper()} больше не считается безопасным!{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Рекомендуется использовать более безопасный алгоритм (SHA256, SHA512 и т.д.){Style.RESET_ALL}")
    
    if data_type == "text" and algorithm in ['sha1', 'md5', 'sha256']:
        print(f"\n{Fore.CYAN}=== Проверка безопасности ==={Style.RESET_ALL}")
        breach_count = check_hash_breach(hash_value)
        if breach_count > 0:
            print(f"{Fore.RED}[!] Этот хэш найден в {breach_count:,} утечках данных!{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] Рекомендуется изменить данные!{Style.RESET_ALL}")
        elif breach_count == 0:
            print(f"{Fore.GREEN}[+] Хэш не найден в известных утечках данных.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[?] Не удалось проверить утечки данных.{Style.RESET_ALL}")

def simulate_processing(desc="Обработка"):
    with tqdm(total=100, desc=desc, 
             bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Fore.RESET)) as pbar:
        for i in range(100):
            time.sleep(0.01)
            pbar.update(1)

def main():
    tool_desc = "Продвинутый генератор и верификатор хэшей"
    tool_features = [
        "Поддержка множества алгоритмов хэширования",
        "Хэширование файлов и текста",
        "Проверка хэшей",
        "Проверка утечек данных",
        "Индикатор прогресса",
        "Рекомендации по безопасности"
    ]
    
    print_banner("Hash Generator & Verifier")
    print_tool_info(tool_desc, tool_features)
    
    parser = argparse.ArgumentParser(description='Генератор и верификатор хэшей')
    parser.add_argument('-t', '--text', help='Текст для хэширования')
    parser.add_argument('-f', '--file', help='Файл для хэширования')
    parser.add_argument('-a', '--algorithm', choices=list(SUPPORTED_ALGORITHMS.keys()),
                        default='sha256', help='Алгоритм хэширования')
    parser.add_argument('-v', '--verify', help='Хэш для проверки')
    
    args = parser.parse_args()
    
    if not (args.text or args.file) or (args.text and args.file):
        print_status("Укажите текст или файл (-t или -f)", "error")
        parser.print_help()
        return
    
    data = args.text if args.text else args.file
    data_type = "text" if args.text else "file"
    
    if args.verify:
        simulate_processing("Проверка хэша")
        print(f"\n{Fore.CYAN}=== Проверка хэша ==={Style.RESET_ALL}")
        if verify_hash(data, args.verify, args.algorithm):
            print_status("Хэш подтвержден!", "success")
        else:
            print_status("Хэш не совпадает!", "error")
    else:
        if data_type == "text":
            simulate_processing("Генерация хэша")
        hash_value = generate_hash(data, args.algorithm)
        if hash_value:
            print_hash_info(args.algorithm, hash_value, data_type)
            
    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nПрограмма остановлена пользователем", "warning")
        sys.exit(0)
