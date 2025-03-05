#!/usr/bin/env python3

import re
import os
import sys
import math
import string
from colorama import init, Fore, Style
import getpass
from tqdm import tqdm
import time
import zxcvbn
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from утилиты.баннер import print_banner, print_tool_info, print_status

init()

def calculate_entropy(password):
    char_counts = {}
    for char in password:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    entropy = 0
    length = len(password)
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy * length

def get_charset_info(password):
    charsets = {
        'lowercase': set(string.ascii_lowercase),
        'uppercase': set(string.ascii_uppercase),
        'digits': set(string.digits),
        'special': set(string.punctuation)
    }
    
    used_chars = {
        'lowercase': set(c for c in password if c in charsets['lowercase']),
        'uppercase': set(c for c in password if c in charsets['uppercase']),
        'digits': set(c for c in password if c in charsets['digits']),
        'special': set(c for c in password if c in charsets['special'])
    }
    
    return {k: len(v) for k, v in used_chars.items()}

def check_common_patterns(password):
    patterns = []
    
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)', password.lower()):
        patterns.append("Последовательные символы")
    
    if re.search(r'(.)\1{2,}', password):
        patterns.append("Повторяющиеся символы")
    
    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn']
    if any(pattern in password.lower() for pattern in keyboard_patterns):
        patterns.append("Клавиатурный паттерн")
    
    if re.search(r'(19|20)\d{2}', password):
        patterns.append("Год")
    
    return patterns

def check_password_strength(password):
    score = 0
    feedback = []
    
    result = zxcvbn.zxcvbn(password)
    score = result['score'] * 20
    
    length = len(password)
    if length < 8:
        feedback.append(("Пароль должен быть не менее 8 символов", "error"))
    elif length < 12:
        feedback.append(("Длина пароля достаточная, но может быть увеличена", "warning"))
        score += length * 0.5
    else:
        score += min(length * 0.7, 20)
    
    charset_info = get_charset_info(password)
    charset_names = {
        'lowercase': 'строчные буквы',
        'uppercase': 'заглавные буквы',
        'digits': 'цифры',
        'special': 'специальные символы'
    }
    
    for charset, count in charset_info.items():
        if count == 0:
            feedback.append((f"Пароль должен содержать {charset_names[charset]}", "error"))
        else:
            score += min(count * 2, 10)
            if count > 2:
                feedback.append((f"Хорошо! Использовано {count} разных {charset_names[charset]}", "success"))
    
    entropy = calculate_entropy(password)
    entropy_score = min(entropy * 2, 20)
    score += entropy_score
    
    if entropy < 3:
        feedback.append(("Низкая энтропия: пароль слишком предсказуем", "error"))
    elif entropy < 4:
        feedback.append(("Средняя энтропия: пароль может быть сложнее", "warning"))
    else:
        feedback.append(("Высокая энтропия: пароль достаточно сложный", "success"))
    
    patterns = check_common_patterns(password)
    if patterns:
        score -= 10 * len(patterns)
        for pattern in patterns:
            feedback.append((f"Обнаружен паттерн: {pattern}", "warning"))
    
    for suggestion in result['feedback']['suggestions']:
        feedback.append((suggestion, "info"))
    
    score = max(0, min(100, score))
    
    return score, feedback

def evaluate_score(score):
    if score >= 80:
        return (f"{Fore.GREEN}Очень сильный{Style.RESET_ALL}", 
                "█" * 5,
                f"{Fore.GREEN}Отлично! Этот пароль очень надежный.{Style.RESET_ALL}")
    elif score >= 60:
        return (f"{Fore.BLUE}Сильный{Style.RESET_ALL}",
                "█" * 4,
                f"{Fore.BLUE}Хорошо! Этот пароль надежный.{Style.RESET_ALL}")
    elif score >= 40:
        return (f"{Fore.YELLOW}Средний{Style.RESET_ALL}",
                "█" * 3,
                f"{Fore.YELLOW}Неплохо, но можно улучшить.{Style.RESET_ALL}")
    elif score >= 20:
        return (f"{Fore.RED}Слабый{Style.RESET_ALL}",
                "█" * 2,
                f"{Fore.RED}Этот пароль недостаточно надежный!{Style.RESET_ALL}")
    else:
        return (f"{Fore.RED}Очень слабый{Style.RESET_ALL}",
                "█" * 1,
                f"{Fore.RED}Этот пароль очень слабый! Смените его немедленно!{Style.RESET_ALL}")

def simulate_analysis():
    stages = ["Анализ символов", "Расчет энтропии", "Проверка паттернов", "Оценка безопасности"]
    for stage in stages:
        with tqdm(total=100, desc=stage, 
                 bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Fore.RESET)) as pbar:
            for i in range(100):
                time.sleep(0.01)
                pbar.update(1)

def calculate_crack_time(score):
    if score >= 80:
        return f"{Fore.GREEN}Сотни лет{Style.RESET_ALL}"
    elif score >= 60:
        return f"{Fore.BLUE}Несколько лет{Style.RESET_ALL}"
    elif score >= 40:
        return f"{Fore.YELLOW}Несколько месяцев{Style.RESET_ALL}"
    elif score >= 20:
        return f"{Fore.RED}Несколько дней{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}Несколько часов{Style.RESET_ALL}"

def main():
    tool_desc = "Продвинутый анализатор паролей"
    tool_features = [
        "Многокритериальный анализ безопасности",
        "Расчет энтропии",
        "Обнаружение распространенных паттернов",
        "Анализ наборов символов",
        "Оценка времени взлома",
        "Подробные рекомендации"
    ]
    
    print_banner("Password Strength Checker")
    print_tool_info(tool_desc, tool_features)
    
    while True:
        password = getpass.getpass(f"\n{Fore.YELLOW}Введите пароль для проверки (q для выхода): {Style.RESET_ALL}")
        
        if password.lower() == 'q':
            break
            
        simulate_analysis()
        score, feedback = check_password_strength(password)
        strength, bars, comment = evaluate_score(score)
        
        print(f"\n{Fore.CYAN}=== Результаты анализа ==={Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Сила пароля: {strength}")
        print(f"{Fore.BLUE}[*] Уровень: {Fore.GREEN}{bars}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Оценка: {comment}")
        print(f"{Fore.BLUE}[*] Баллы: {score:.1f}/100{Style.RESET_ALL}")
        
        if feedback:
            print(f"\n{Fore.CYAN}=== Детальный анализ ==={Style.RESET_ALL}")
            for msg, level in feedback:
                if level == "error":
                    print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")
                elif level == "warning":
                    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
                elif level == "success":
                    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.BLUE}[*] {msg}{Style.RESET_ALL}")
        
        entropy = calculate_entropy(password)
        print(f"\n{Fore.CYAN}=== Технические детали ==={Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Энтропия: {entropy:.2f} bits{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Время взлома: {calculate_crack_time(score)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nПрограмма остановлена пользователем", "warning")
        sys.exit(0)
