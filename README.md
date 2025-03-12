# CST-scan
Сканирование активов с помощью masscan, после результаты передаются в nmap для определения сервиса и уязвимостей.

Как использовать:
Запуск скрипта:
```python nmap_scanner.py --ip-list ip_list.txt --ports-file top1000ports.txt --masscan-output ScanIP_list.json --nmap-output results.xlsx --rate 300 --threads 40 --timeout 300```

Аргументы:

--ip-list: Путь к файлу ip_list.txt.

--ports-file: Путь к файлу top1000ports.txt (по умолчанию top1000ports.txt).

--masscan-output: Путь к выходному файлу Masscan (по умолчанию ScanIP_list.json).

--nmap-output: Путь к выходному файлу Nmap (по умолчанию nmap_scan_results.xlsx).

--rate: Скорость сканирования Masscan (по умолчанию 300).

--threads: Количество потоков (по умолчанию 40).

--timeout: Таймаут для выполнения каждой задачи (по умолчанию 300 секунд).

Пример вывода:
```CyberSecurityTeam

2023-10-10 12:00:00 - INFO - Запуск masscan: sudo masscan -iL ip_list.txt --rate 300 -p80,443,22... -oJ ScanIP_list.json
2023-10-10 12:00:10 - INFO - Результаты masscan сохранены в ScanIP_list.json
Определение сервисов: 100%|████████████████████| 10/10 [00:10<00:00,  1.00it/s]
Сканирование уязвимостей: 100%|████████████████| 10/10 [00:20<00:00,  2.00it/s]
2023-10-10 12:00:30 - INFO - Сканирование завершено за 30.00 секунд.
2023-10-10 12:00:30 - INFO - Результаты сохранены в файл: results.xlsx```
