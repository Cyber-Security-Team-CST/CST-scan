import json
import time
import logging
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from openpyxl import Workbook
from tqdm import tqdm
from colorama import Fore, Style
import re
import sys
import os

# Логотип "CyberSecurityTeam"
CYBER_SECURITY_TEAM_LOGO = r"""
 ██████╗███████╗████████╗   ███████╗ ██████╗ █████╗ ███╗   ██╗                                                                                     
██╔════╝██╔════╝╚══██╔══╝   ██╔════╝██╔════╝██╔══██╗████╗  ██║                                                                                     
██║     ███████╗   ██║█████╗███████╗██║     ███████║██╔██╗ ██║                                                                                     
██║     ╚════██║   ██║╚════╝╚════██║██║     ██╔══██║██║╚██╗██║                                                                                     
╚██████╗███████║   ██║      ███████║╚██████╗██║  ██║██║ ╚████║                                                                                     
 ╚═════╝╚══════╝   ╚═╝      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                                                                                     
                                                                                                                                                   
 ██████╗██╗   ██╗██████╗ ███████╗██████╗       ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗  ████████╗███████╗ █████╗ ███╗   ███╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗      ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝  ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╗███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝█████╗██║   █████╗  ███████║██╔████╔██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════╝╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝ ╚════╝██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║      ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║        ██║   ███████╗██║  ██║██║ ╚═╝ ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝      ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
                                                                                                                                                   
██╗   ██╗███████╗██████╗ ███████╗██╗ ██████╗ ███╗   ██╗      ██████╗                                                                               
██║   ██║██╔════╝██╔══██╗██╔════╝██║██╔═══██╗████╗  ██║      ╚════██╗                                                                              
██║   ██║█████╗  ██████╔╝███████╗██║██║   ██║██╔██╗ ██║█████╗ █████╔╝                                                                              
╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██║██║   ██║██║╚██╗██║╚════╝██╔═══╝                                                                               
 ╚████╔╝ ███████╗██║  ██║███████║██║╚██████╔╝██║ ╚████║      ███████╗                                                                              
  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝      ╚══════╝                                                                              
 
 _._     _,-'""`-._
(,-.`._,'(       |\`-/| 
    `-.-' \ )-`( , o o)
          `-    \`_`"'-             
                                            |\__/,|   (`\
                                          _.|o o  |_   ) )
                                        -(((---(((--------                                                         
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

# Валидация IP и порта
def validate_ip(ip):
    pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return pattern.match(ip) is not None

def validate_port(port):
    return 1 <= port <= 65535

# Запуск masscan
def run_masscan(ip_list_file, ports_file, output_file, rate):
    if not os.path.exists(ip_list_file):
        logging.error(f"Файл {ip_list_file} не найден.")
        sys.exit(1)
    if not os.path.exists(ports_file):
        logging.error(f"Файл {ports_file} не найден.")
        sys.exit(1)

    # Чтение портов из файла
    with open(ports_file, 'r') as file:
        ports = file.read().strip().replace('\n', ',')

    # Команда masscan
    command = f"sudo masscan -iL {ip_list_file} --rate {rate} -p{ports} -oJ {output_file}"
    logging.info(f"Запуск masscan: {command}")

    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Результаты masscan сохранены в {output_file}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Ошибка при выполнении masscan: {e}")
        sys.exit(1)

# Функция для запуска nmap и определения сервиса
def determine_service(ip, port, timeout):
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

# Функция для запуска nmap с использованием скрипта vuln
def run_nmap_vuln_scan(ip, port, timeout, nse_script=None):
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

# Функция для сохранения результатов в Excel
def save_results_to_excel(services, vulnerabilities, output_file):
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

    # Сохранение файла
    wb.save(output_file)
    logging.info(f"Результаты сохранены в файл: {output_file}")

# Основная функция
def main():
    # Вывод логотипа
    print(Fore.CYAN + CYBER_SECURITY_TEAM_LOGO + Style.RESET_ALL)

    parser = argparse.ArgumentParser(description="Сканирование сети с помощью Masscan и Nmap.")
    parser.add_argument("--ip-list", required=True, help="Путь к файлу ip_list.txt")
    parser.add_argument("--ports-file", default="top1000ports.txt", help="Путь к файлу top1000ports.txt (по умолчанию: top1000ports.txt)")
    parser.add_argument("--masscan-output", default="ScanIP_list.json", help="Путь к выходному файлу Masscan (по умолчанию: ScanIP_list.json)")
    parser.add_argument("--nmap-output", default="nmap_scan_results.xlsx", help="Путь к выходному файлу Nmap (по умолчанию: nmap_scan_results.xlsx)")
    parser.add_argument("--rate", type=int, default=300, help="Скорость сканирования Masscan (по умолчанию: 300)")
    parser.add_argument("--threads", type=int, default=40, help="Количество потоков (по умолчанию: 40)")
    parser.add_argument("--timeout", type=int, default=300, help="Таймаут для выполнения каждой задачи в секундах (по умолчанию: 300)")
    parser.add_argument("--service-scan", action="store_true", help="Выполнить только сканирование сервисов")
    parser.add_argument("--vuln-scan", action="store_true", help="Выполнить только сканирование уязвимостей")
    parser.add_argument("--nse-script", type=str, help="Указать пользовательский скрипт NSE для сканирования")
    parser.add_argument("--quiet", action="store_true", help="Минимальный вывод информации, только прогресс")
    args = parser.parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    # Запуск Masscan
    run_masscan(args.ip_list, args.ports_file, args.masscan_output, args.rate)

    # Чтение результатов Masscan
    with open(args.masscan_output, 'r') as file:
        data = json.load(file)

    services = []
    vulnerabilities = []

    # Подсчёт общего количества задач
    total_tasks = sum(1 for entry in data for port_info in entry['ports'] if port_info['status'] == 'open') * 2
    completed_tasks = 0

    start_time = time.time()

    # Создаём пул потоков
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
                        logging.info(f"Сканирование IP: {ip}, порт: {port}")

                        # Определение сервиса
                        future = executor.submit(determine_service, ip, port, args.timeout)
                        future.ip = ip  # Сохраняем IP в объекте Future
                        future.port = port  # Сохраняем порт в объекте Future
                        futures_service.append(future)

            # Прогресс-бар для этапа 1
            with tqdm(total=len(futures_service), desc="Определение сервисов", disable=args.quiet) as pbar:
                for future in as_completed(futures_service):
                    service, full_output = future.result()
                    ip = future.ip  # Получаем IP из объекта Future
                    port = future.port  # Получаем порт из объекта Future
                    logging.info(f"Определён сервис: {service} для {ip}:{port}")
                    services.append({
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "full_output": full_output
                    })

                    # Запуск nmap с использованием скрипта vuln, если не указано только сканирование сервисов
                    if not args.service_scan:
                        future_vuln = executor.submit(run_nmap_vuln_scan, ip, port, args.timeout, args.nse_script)
                        future_vuln.ip = ip  # Сохраняем IP в объекте Future
                        future_vuln.port = port  # Сохраняем порт в объекте Future
                        futures_vuln.append(future_vuln)

                    pbar.update(1)

        # Этап 2: Сканирование уязвимостей
        if not args.service_scan:
            with tqdm(total=len(futures_vuln), desc="Сканирование уязвимостей", disable=args.quiet) as pbar:
                for future in as_completed(futures_vuln):
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                    pbar.update(1)

    execution_time = time.time() - start_time
    logging.info(f"Сканирование завершено за {execution_time:.2f} секунд.")

    # Сохранение результатов в Excel
    save_results_to_excel(services, vulnerabilities, args.nmap_output)

# Запуск основной функции
if __name__ == "__main__":
    main()
