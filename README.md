# 👁️ Telegram Traffic Sniffer

Этот проект представляет собой **инструмент пассивного мониторинга сетевого трафика Telegram**.  
С помощью Python и библиотеки Pyshark вы сможете отслеживать IP-адреса и протоколы, используемые Telegram на вашем компьютере.

---

## 🚀 Особенности

- 🔍 Автоматический захват трафика на выбранном сетевом интерфейсе  
- 📡 Определение, принадлежит ли IP адрес Telegram (поддержка одиночных IP и подсетей CIDR)  
- 📝 Запись обнаруженного трафика в лог-файл с временными метками  
- 💻 Вывод результатов в консоль в удобном формате JSON  

---

## 🎯 Целевая аудитория

Этот инструмент будет полезен:

- Всем, кто интересуется сетевой безопасностью и мониторингом трафика  
- Исследователям Telegram протоколов  
- Энтузиастам и студентам, изучающим сетевой анализ  

---

## 🧰 Используемые технологии

- Python 3.7+  
- Pyshark (обёртка для tshark)  
- Tshark (терминальная версия Wireshark)  

---

## 🔧 Установка и запуск
---
### 1. Установка tshark

- Windows: скачайте и установите Wireshark, убедитесь, что опция tshark включена  
- Linux (Debian/Ubuntu):  
  ```bash
  sudo apt-get install tshark
---
### MacOS:
  ```bash
  brew install wireshark
```
## Установка pyshark
  ```bash
  pip install pyshark
```
## Запуск скрипта
```bash
python telegram_sniffer.py
```
Если сетевой интерфейс не будет определён автоматически, скрипт попросит ввести его вручную (например, Wi-Fi или eth0).

---

## ⚠️ Важно
Используйте инструмент только на своих сетях и с разрешения

Скрипт не перехватывает содержимое сообщений, а только метаданные трафика

Соблюдайте законодательство своей страны в области мониторинга сети

----

👩‍💻 Разработчик
@gizemnwr

---

📜 Лицензия
MIT License © 2025

