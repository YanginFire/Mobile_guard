import os
import sys
from pathlib import Path
from datetime import datetime

# Добавляем путь для импорта модуля отчетов
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

# Импортируем модуль отчетов
try:
    from report_compose import ReportComposer, save_to_json, save_to_csv
    REPORT_COMPOSER_AVAILABLE = True
except ImportError as e:
    print(f"Не удалось импортировать модуль отчетов: {e}")
    REPORT_COMPOSER_AVAILABLE = False


def analyze_apk(apk_path):
    """Анализирует APK файл и возвращает разрешения и интенты"""
    if not ANDROGUARD_AVAILABLE:
        print("Androguard не установлен. Используется демо-режим.")
        # Демо-данные для тестирования
        permissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.READ_EXTERNAL_STORAGE"
        ]

        intents = {
            "com.example.MainActivity": {
                "actions": ["android.intent.action.MAIN"],
                "categories": ["android.intent.category.LAUNCHER"],
                "data": []
            }
        }
        return permissions, intents

    try:
        apk_info, dex_code, analysis = AnalyzeAPK(apk_path)
        permissions = apk_info.get_permissions() or []
        intents = {}

        for activity in apk_info.get_activities():
            intent_filters = {
                'actions': apk_info.get_intent_filters(activity, 'action') or [],
                'categories': apk_info.get_intent_filters(activity, 'category') or [],
                'data': apk_info.get_intent_filters(activity, 'data') or [],
            }
            intents[activity] = intent_filters

        return permissions, intents
    except Exception as e:
        print(f"Ошибка при анализе APK: {e}")
        return [], {}


def process_apk(apk_path):
    """Обрабатывает APK файл и возвращает структурированные данные"""
    analyzed_data = []
    try:
        permissions, intents = analyze_apk(apk_path)

        analyzed_data.append({
            'APK': os.path.basename(apk_path),
            'Path': apk_path,
            'Permissions': permissions,
            'Intents': intents
        })
    except Exception as e:
        print(f"Ошибка обработки APK {apk_path}: {e}")

    return analyzed_data


def analyze_single_apk(apk_path, output_dir=None):
    """Анализирует один APK файл и сохраняет результаты"""
    if not os.path.exists(apk_path):
        print(f"Файл не найден: {apk_path}")
        return None

    # Если не указана директория для сохранения, используем текущую
    if output_dir is None:
        output_dir = os.path.dirname(apk_path) or "."

    # Анализируем APK
    data = process_apk(apk_path)

    if data and REPORT_COMPOSER_AVAILABLE:
        apk_name = os.path.splitext(os.path.basename(apk_path))[0]
        
        # Создаем компоновщик отчетов
        composer = ReportComposer(output_dir)
        
        # Создаем базовую информацию о APK для отчета
        apk_info = {
            'name': data[0]['APK'],
            'path': data[0]['Path'],
            'size': os.path.getsize(apk_path),
            'last_modified': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Создаем структурированный отчет
        report = composer.compose_report(apk_info, data[0])
        
        # Сохраняем отчет в различных форматах
        saved_files = composer.save_report(
            report=report,
            apk_name=apk_name,
            formats=['json', 'txt', 'csv']
        )
        
        print(f"Анализ завершен для {apk_path}")
        print(f"Сохраненные отчеты: {saved_files}")
        
        return {
            'raw_data': data,
            'structured_report': report,
            'saved_files': saved_files
        }
    elif data:
        apk_name = os.path.splitext(os.path.basename(apk_path))[0]
        
        # Сохраняем результаты
        csv_path = os.path.join(output_dir, f"{apk_name}_analysis.csv")
        json_path = os.path.join(output_dir, f"{apk_name}_analysis.json")

        save_to_csv(data, csv_path)
        save_to_json(data, json_path)

        print(f"Анализ завершен для {apk_path}")
        return data

    return None

def save_to_csv_old(data, output_file):
    if REPORT_COMPOSER_AVAILABLE:
        return save_to_csv(data, output_file)
    else:
        import csv
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['APK', 'Permissions', 'Intents']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for entry in data:
                    writer.writerow({
                        'APK': entry['APK'],
                        'Permissions': ', '.join(entry['Permissions']) if entry['Permissions'] else 'None',
                        'Intents': str(entry['Intents'])
                    })
            print(f"Данные сохранены в {output_file}")
        except Exception as e:
            print(f"Ошибка сохранения CSV: {e}")


def save_to_json_old(data, output_file):
    if REPORT_COMPOSER_AVAILABLE:
        return save_to_json(data, output_file)
    else:
        import json
        try:
            with open(output_file, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=4, ensure_ascii=False)
            print(f"Данные сохранены в {output_file}")
        except Exception as e:
            print(f"Ошибка сохранения JSON: {e}")