import pyshark
import ipaddress
import json
from datetime import datetime
import platform
import sys

# Список IP-адресов и подсетей Telegram (CIDR и одиночные IP)
TELEGRAM_IP_BLOCKS = [
    "149.154.167.51",
    "149.154.167.91",
    "149.154.167.99",
    "91.108.56.0/22",
    "149.154.160.0/20",
]

def ip_принадлежит_телеграм(ip_str):
    """
    Проверяет, принадлежит ли IP-адрес к диапазонам Telegram.
    Поддерживается проверка одиночных IP и подсетей CIDR.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Некорректный IP-адрес
        return False

    for block in TELEGRAM_IP_BLOCKS:
        try:
            if '/' in block:
                сеть = ipaddress.ip_network(block, strict=False)
                if ip in сеть:
                    return True
            else:
                if ip_str == block:
                    return True
        except ValueError:
            continue
    return False

def определить_сетевой_интерфейс():
    """
    Пытается автоматически определить сетевой интерфейс по ОС.
    Если не удалось — возвращает None.
    """
    система = platform.system()
    if система == "Windows":
        return "Wi-Fi"
    elif система == "Linux":
        return "eth0"
    elif система == "Darwin":
        return "en0"
    else:
        return None

def main():
    print("=== Прослушиватель трафика Telegram ===\n")

    интерфейс = определить_сетевой_интерфейс()
    if интерфейс is None:
        print("Не удалось автоматически определить сетевой интерфейс.")
        интерфейс = input("Пожалуйста, введите интерфейс вручную (например, eth0, Wi-Fi): ").strip()

    print(f"\n[*] Запуск прослушивания на интерфейсе: {интерфейс}\n")

    try:
        захват = pyshark.LiveCapture(interface=интерфейс)
    except Exception as ошибка:
        print(f"[!] Ошибка при подключении к интерфейсу: {ошибка}")
        sys.exit(1)

    имя_лога = f"telegram_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    print(f"[i] Все обнаруженные пакеты будут записаны в файл: '{имя_лога}'\n")

    with open(имя_лога, 'w', encoding='utf-8') as файл_лога:
        try:
            for пакет in захват.sniff_continuously():
                try:
                    ip_источник = пакет.ip.src
                    ip_назначение = пакет.ip.dst
                    протокол = пакет.transport_layer
                    время = пакет.sniff_time.strftime("%Y-%m-%d %H:%M:%S")

                    if ip_принадлежит_телеграм(ip_источник) or ip_принадлежит_телеграм(ip_назначение):
                        запись = {
                            "время": время,
                            "ip_источник": ip_источник,
                            "ip_назначение": ip_назначение,
                            "протокол": протокол
                        }
                        json_запись = json.dumps(запись, indent=2, ensure_ascii=False)
                        print("[+] Обнаружен трафик Telegram:")
                        print(json_запись)
                        print("-" * 40)

                        файл_лога.write(json_запись + "\n")
                        файл_лога.flush()

                except AttributeError:
                    # Пакет без IP или transport layer пропускаем
                    continue
        except KeyboardInterrupt:
            print("\n[!] Прослушивание остановлено пользователем.")
            print(f"[i] Логи сохранены в файл '{имя_лога}'.")
            sys.exit(0)

if __name__ == "__main__":
    main()
