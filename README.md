# CST-scan
Сканирование активов с помощью masscan, после результаты передаются в nmap для определения сервиса и уязвимостей.

Как использовать:
Запуск скрипта:
python nmap_scanner.py --ip-list ip_list.txt --ports-file top1000ports.txt --masscan-output ScanIP_list.json --nmap-output results.xlsx --rate 300 --threads 40 --timeout 300
