#!/usr/bin/env python3
import json
import time
import logging
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from openpyxl import Workbook
from tqdm import tqdm
from colorama import Fore, Style, init
import re
import sys
import os
import ipaddress

# Инициализация colorama
init()

# Логотип "CyberSecurityTeam"
CYBER_SECURITY_TEAM_LOGO = r"""
 .o88b. .d8888. d888888b        .d8888.  .o88b.  .d8b.  d8b   db                                                                                               
d8P  Y8 88'  YP `~~88~~'        88'  YP d8P  Y8 d8' `8b 888o  88                                                                                               
8P      `8bo.      88           `8bo.   8P      88ooo88 88V8o 88                                                                                               
8b        `Y8b.    88    C8888D   `Y8b. 8b      88~~~88 88 V8o88                                                                                               
Y8b  d8 db   8D    88           db   8D Y8b  d8 88   88 88  V888                                                                                               
 `Y88P' `8888Y'    YP           `8888Y'  `Y88P' YP   YP VP   V8P  
 
                                                    VERSION-3                                                                                          
                                                                                                                                                       
43 59 42 45 52 2D 53 45 43 55 52 49 54 59 2D 54 45 41 4D                                                                                                                                                        

    |\__/,|   (`\
  _.|o o  |_   ) )
-(((---(((-----arp

 _._     _,-'""`-._
(,-.`._,'(       |\`-/|
    `-.-\' \ )-`( , o o)
          `-    \`_`"'-  port

    /\_/\           ___
   = o_o =_______    \ \    service
    __^      __(  \.__) )
(@)<_____>__(_____)____/

          .-n=m-.
      ,  /=a=p=s=\ .--.
     _|\|=c=a=n=v=|    \
 __.'  O`\=u=l=n=(`\   /
 '.  O  4/`|.-""'`\ \ ;'`)   .---.
   \   .'  /   .--'  |_.'   / .-._)
    `)  _.'   /     /`-.__.' /
     `'-.____;     /'-.___.-'
              `""'`
              
"""

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format=f"{Fore.GREEN}%(asctime)s - %(levelname)s - %(message)s{Style.RESET_ALL}",
    handlers=[
        logging.FileHandler("nmap_scan.log"),
        logging.StreamHandler()
    ]
)

def validate_ip(ip):
    """Проверка корректности IP-адреса."""
    pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return pattern.match(ip) is not None

def validate_port(port):
    """Проверка корректности номера порта."""
    return 1 <= port <= 65535

def arp_discovery(subnet: str, interface: str = "eth0") -> list:
    """Обнаружение хостов через ARP (для локальных сетей /24 и больше)."""
    try:
        cmd = ["arp-scan", "--localnet", "-I", interface, subnet]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", result.stdout)
        return list(set(ips))
    except Exception as e:
        logging.error(f"ARP-сканирование {subnet} не удалось: {e}")
        return []

def nmap_ping_scan(subnet: str) -> list:
    """Обнаружение хостов через Nmap (ICMP + TCP SYN)."""
    try:
        cmd = [
            "nmap", "-sn", "-n",
            "-PE", "-PS21,22,80,443,445",
            "--max-retries", "1",
            "--host-timeout", "5s",
            "-oG", "-",
            subnet
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        ips = re.findall(r"Host: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", result.stdout)
        return ips
    except Exception as e:
        logging.error(f"Nmap ping-сканирование {subnet} не удалось: {e}")
        return []

def generate_target_list(subnets: list, interface: str = "eth0") -> str:
    """Генерирует файл с живыми хостами через ARP + Nmap."""
    live_hosts = set()

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for subnet in subnets:
            network = ipaddress.ip_network(subnet, strict=False)
            if network.prefixlen >= 24:  # Локальная сеть -> ARP
                futures.append(executor.submit(arp_discovery, subnet, interface))
            else:  # Крупная подсеть -> Nmap
                futures.append(executor.submit(nmap_ping_scan, subnet))

        for future in as_completed(futures):
            live_hosts.update(future.result())

    temp_file = "live_hosts.txt"
    with open(temp_file, "w") as f:
        f.write("\n".join(live_hosts))

    logging.info(f"Обнаружено {len(live_hosts)} хостов. Файл: {temp_file}")
    return temp_file

def run_masscan(ip_list_file, ports_file, output_file, rate):
    """Запуск masscan для сканирования портов."""
    if not os.path.exists(ip_list_file):
        logging.error(f"Файл {ip_list_file} не найден.")
        sys.exit(1)
    if not os.path.exists(ports_file):
        logging.error(f"Файл {ports_file} не найден.")
        sys.exit(1)

    with open(ports_file, 'r') as file:
        ports = file.read().strip().replace('\n', ',')

    command = f"sudo masscan -iL {ip_list_file} --rate {rate} -p{ports} -oJ {output_file}"
    logging.info(f"Запуск masscan: {command}")

    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Результаты masscan сохранены в {output_file}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Ошибка при выполнении masscan: {e}")
        sys.exit(1)

def determine_service(ip, port, timeout):
    """Определение сервиса на порту с помощью nmap."""
    command = f"nmap -sV -p {port} {ip}"
    try:
        process = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        if process.returncode != 0:
            logging.error(f"Ошибка при выполнении nmap: {process.stderr}")
            return "Unknown", ""

        service = "Unknown"
        for line in process.stdout.splitlines():
            if f"{port}/tcp" in line:
                service = line.split()[-1]
        return service, process.stdout
    except subprocess.TimeoutExpired:
        logging.error(f"Таймаут при сканировании {ip}:{port}")
        return "Unknown", ""
    except Exception as e:
        logging.error(f"Исключение при определении сервиса: {e}")
        return "Unknown", ""

def run_nmap_vuln_scan(ip, port, timeout, nse_script=None):
    """Сканирование уязвимостей с помощью nmap."""
    command = f"nmap -sV -p {port} --script {nse_script if nse_script else 'vuln'} {ip}"
    try:
        process = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        if process.returncode != 0:
            logging.error(f"Ошибка при выполнении nmap: {process.stderr}")
            return None

        full_output = process.stdout
        vulnerabilities = []
        for line in full_output.splitlines():
            if "CVE-" in line:
                vulnerabilities.append(line.strip())

        return {
            "ip": ip,
            "port": port,
            "vulnerabilities": vulnerabilities,
            "full_output": full_output
        }
    except subprocess.TimeoutExpired:
        logging.error(f"Таймаут при сканировании {ip}:{port}")
        return None
    except Exception as e:
        logging.error(f"Исключение при выполнении nmap с скриптом vuln: {e}")
        return None

def save_results_to_excel(services, vulnerabilities, output_file):
    """Сохранение результатов в Excel файл."""
    wb = Workbook()

    # Лист с сервисами
    ws_services = wb.active
    ws_services.title = "Services"
    ws_services.append(["IP", "Port", "Service", "Full Output"])
    for service in services:
        ws_services.append([service["ip"], service["port"], service["service"], service["full_output"]])

    # Лист с уязвимостями
    ws_vulns = wb.create_sheet(title="Vulnerabilities")
    ws_vulns.append(["IP", "Port", "Vulnerability"])
    for vuln in vulnerabilities:
        if vuln["vulnerabilities"]:
            for vulnerability in vuln["vulnerabilities"]:
                ws_vulns.append([vuln["ip"], vuln["port"], vulnerability])

    wb.save(output_file)
    logging.info(f"Результаты сохранены в файл: {output_file}")

def main():
    print(Fore.CYAN + CYBER_SECURITY_TEAM_LOGO + Style.RESET_ALL)

    parser = argparse.ArgumentParser(description="Сканирование сети с помощью ARP/Nmap + Masscan + Nmap.")
    parser.add_argument("--ip-list", help="Файл с IP/подсетями для сканирования")
    parser.add_argument("--ports-file", default="top1000ports.txt", help="Файл с портами для сканирования")
    parser.add_argument("--masscan-output", default="ScanIP_list.json", help="Выходной файл Masscan")
    parser.add_argument("--nmap-output", default="nmap_scan_results.xlsx", help="Выходной файл Nmap")
    parser.add_argument("--rate", type=int, default=300, help="Скорость сканирования Masscan")
    parser.add_argument("--threads", type=int, default=40, help="Количество потоков")
    parser.add_argument("--timeout", type=int, default=300, help="Таймаут для Nmap")
    parser.add_argument("--service-scan", action="store_true", help="Только сканирование сервисов")
    parser.add_argument("--vuln-scan", action="store_true", help="Только сканирование уязвимостей")
    parser.add_argument("--nse-script", help="Пользовательский NSE скрипт")
    parser.add_argument("--quiet", action="store_true", help="Минимальный вывод")
    parser.add_argument("--discover", action="store_true", help="Обнаружение живых хостов перед сканированием")
    parser.add_argument("--interface", default="eth0", help="Сетевой интерфейс для ARP-сканирования")
    args = parser.parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    # Обнаружение живых хостов
    if args.discover:
        if not args.ip_list:
            logging.error("Для --discover требуется --ip-list с подсетями!")
            sys.exit(1)

        with open(args.ip_list, "r") as f:
            subnets = [line.strip() for line in f if line.strip()]

        logging.info("Запуск обнаружения живых хостов...")
        args.ip_list = generate_target_list(subnets, args.interface)

    # Проверка наличия файла с целями
    if not os.path.exists(args.ip_list):
        logging.error(f"Файл {args.ip_list} не найден!")
        sys.exit(1)

    # Запуск Masscan
    run_masscan(args.ip_list, args.ports_file, args.masscan_output, args.rate)

    # Чтение результатов Masscan
    with open(args.masscan_output, 'r') as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            logging.error(f"Ошибка чтения {args.masscan_output}. Файл пуст или поврежден.")
            sys.exit(1)

    services = []
    vulnerabilities = []
    start_time = time.time()

    # Сканирование сервисов и уязвимостей
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures_service = []
        futures_vuln = []

        # Этап 1: Определение сервисов
        if not args.vuln_scan:
            for entry in data:
                ip = entry['ip']
                for port_info in entry['ports']:
                    if port_info['status'] == 'open':
                        port = port_info['port']
                        if not validate_ip(ip) or not validate_port(port):
                            logging.warning(f"Некорректный IP или порт: {ip}:{port}")
                            continue

                        future = executor.submit(determine_service, ip, port, args.timeout)
                        future.ip = ip
                        future.port = port
                        futures_service.append(future)

            # Обработка результатов сканирования сервисов
            with tqdm(total=len(futures_service), desc="Определение сервисов", disable=args.quiet) as pbar:
                for future in as_completed(futures_service):
                    service, full_output = future.result()
                    services.append({
                        "ip": future.ip,
                        "port": future.port,
                        "service": service,
                        "full_output": full_output
                    })
                    pbar.update(1)

        # Этап 2: Сканирование уязвимостей
        if not args.service_scan:
            for entry in data:
                ip = entry['ip']
                for port_info in entry['ports']:
                    if port_info['status'] == 'open':
                        port = port_info['port']
                        if not validate_ip(ip) or not validate_port(port):
                            continue

                        future = executor.submit(
                            run_nmap_vuln_scan,
                            ip, port, args.timeout, args.nse_script
                        )
                        futures_vuln.append(future)

            # Обработка результатов сканирования уязвимостей
            with tqdm(total=len(futures_vuln), desc="Сканирование уязвимостей", disable=args.quiet) as pbar:
                for future in as_completed(futures_vuln):
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                    pbar.update(1)

    execution_time = time.time() - start_time
    logging.info(f"Сканирование завершено за {execution_time:.2f} секунд.")

    # Сохранение результатов
    save_results_to_excel(services, vulnerabilities, args.nmap_output)

if __name__ == "__main__":
    main()
