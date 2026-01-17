import flet as ft
import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Импорт модулей для метрик
try:
    from prometheus import (
        record_apk_analysis,
        record_apk_detection,
        record_report_generation,
        record_file_operation,
        update_apk_files_count,
        update_dangerous_permissions_count
    )
    PROMETHEUS_AVAILABLE = True
except ImportError as e:
    print(f"Prometheus metrics not available: {e}")
    PROMETHEUS_AVAILABLE = False

# Добавляем путь к модулю анализатора
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from apk_analyzer import analyze_single_apk
    APK_ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"Не удалось импортировать модуль анализатора: {e}")
    APK_ANALYZER_AVAILABLE = False

# Пытаемся импортировать модуль отчетов
try:
    from report_compose import ReportComposer
    REPORT_COMPOSER_AVAILABLE = True
except ImportError:
    REPORT_COMPOSER_AVAILABLE = False
    print("Модуль отчетов не доступен. Используется упрощенный режим.")


class APKAnalyzerApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Mobile Guard"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.padding = 10
        self.page.scroll = ft.ScrollMode.AUTO

        # Директории для поиска APK
        self.download_dirs = []
        self.setup_directories()

        # Подозрительные слова
        self.SUSPICIOUS_WORDS = [
            "hack", "crack", "mod", "premium", "free", "cheat",
            "virus", "trojan", "malware", "spyware", "keylogger",
            "bot", "exploit", "root", "jailbreak", "adware", "ransomware"
        ]

        # Подозрительные разрешения
        self.DANGEROUS_PERMISSIONS = [
            "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS",
            "WRITE_CONTACTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG", "WRITE_CALL_LOG"
        ]

        # Инициализация UI
        self.init_ui()

    def setup_directories(self):
        """Настраивает директории для поиска APK файлов"""
        # Сначала проверяем тестовую папку в проекте
        test_dir = os.path.join(os.path.dirname(__file__), "downloads_test")
        if os.path.exists(test_dir):
            self.download_dirs.append(test_dir)
            print(f"Добавлена тестовая директория: {test_dir}")

        # Android пути
        android_paths = [
            "/sdcard/Download/",
            "/sdcard/",
            "/storage/emulated/0/Download/",
            "/storage/emulated/0/",
            "/storage/self/primary/Download/"
        ]

        # Проверяем существующие пути на устройстве
        for path in android_paths:
            if os.path.exists(path):
                self.download_dirs.append(path)
                print(f"Добавлена Android директории: {path}")

        # Если нет директорий, создаем тестовую
        if not self.download_dirs:
            default_dir = os.path.join(os.path.dirname(__file__), "downloads")
            os.makedirs(default_dir, exist_ok=True)
            self.download_dirs.append(default_dir)

    def determine_maliciousness(self, apk_name, permissions=None):
        """Определяет уровень вредоносности на основе имени и разрешений"""
        apk_name_lower = apk_name.lower()
        suspicious_count = 0
        dangerous_count = 0

        # Проверяем подозрительные слова в названии
        for word in self.SUSPICIOUS_WORDS:
            if word in apk_name_lower:
                suspicious_count += 1

        # Проверяем опасные разрешения
        if permissions:
            for perm in self.DANGEROUS_PERMISSIONS:
                if any(perm.lower() in p.lower() for p in permissions):
                    dangerous_count += 1
                    suspicious_count += 0.5  # Половина балла за опасное разрешение
        
        # Обновляем метрики опасных разрешений
        if PROMETHEUS_AVAILABLE:
            update_dangerous_permissions_count(dangerous_count)

        if suspicious_count >= 2:
            risk_level = "высокая"
            color = ft.Colors.RED
        elif suspicious_count >= 1:
            risk_level = "средняя"
            color = ft.Colors.ORANGE
        else:
            risk_level = "низкая"
            color = ft.Colors.GREEN
        
        # Записываем метрику обнаружения
        if PROMETHEUS_AVAILABLE:
            if risk_level == "высокая":
                record_apk_detection(risk_level='high')
            elif risk_level == "средняя":
                record_apk_detection(risk_level='medium')
            else:
                record_apk_detection(risk_level='low')

        return risk_level, color

    def get_android_icon(self, color):
        return ft.Icon(ft.Icons.ANDROID, color=color, size=24)

    def get_maliciousness_text(self, level, color):
        return ft.Text(f"Вредоносность: {level}", size=12, color=color, weight=ft.FontWeight.BOLD)

    def find_apk_files(self):
        """Находит все APK файлы в указанных директориях"""
        apk_files = []

        for directory in self.download_dirs:
            try:
                path = Path(directory)
                if path.exists():
                    # Ищем APK файлы
                    for apk in path.rglob("*.apk"):
                        try:
                            # Получаем базовую информацию без полного анализа
                            apk_info = {
                                "name": apk.name,
                                "path": str(apk),
                                "size": apk.stat().st_size,
                                "last_modified": datetime.fromtimestamp(apk.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
                                "permissions": []  # Будет заполнено при анализе
                            }
                            apk_files.append(apk_info)
                        except Exception as e:
                            print(f"Ошибка чтения файла {apk}: {e}")
                            continue
            except Exception as e:
                print(f"Ошибка доступа к директории {directory}: {e}")
                continue

        # Если файлов не найдено, создаем демо-файлы
        if not apk_files:
            apk_files = self.create_demo_files()

        return apk_files[:100]  # Ограничиваем 100 файлами

    def create_demo_files(self):
        """Создает демо-файлы для тестирования"""
        demo_files = []
        test_dir = os.path.join(os.path.dirname(__file__), "downloads_test")
        os.makedirs(test_dir, exist_ok=True)

        demos = [
            {"name": "FreePremiumHack.apk", "size": 1024000},
            {"name": "TestApp.apk", "size": 2048000},
            {"name": "VirusCleanerMod.apk", "size": 3072000},
            {"name": "SafeApp.apk", "size": 1500000},
            {"name": "CrackGameFree.apk", "size": 2500000},
        ]

        for demo in demos:
            # Создаем пустой файл для демо
            demo_path = os.path.join(test_dir, demo["name"])
            if not os.path.exists(demo_path):
                with open(demo_path, 'wb') as f:
                    f.write(b'\x00' * 100)  # Минимальный размер

            demo_info = {
                "name": demo["name"],
                "path": demo_path,
                "size": demo["size"],
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "permissions": []
            }
            demo_files.append(demo_info)

        return demo_files

    def init_ui(self):
        """Инициализирует пользовательский интерфейс"""
        # Элементы UI
        self.apk_list_view = ft.ListView(expand=True, spacing=10)
        self.file_count_text = ft.Text("", size=16)
        self.status_text = ft.Text("", size=14, color=ft.Colors.BLUE)

        # Навигационная панель
        self.nav_bar = ft.NavigationBar(
            on_change=self.change_page,
            selected_index=0,
            destinations=[
                ft.NavigationBarDestination(
                    icon=ft.Icons.HOME,
                    selected_icon=ft.Icons.HOME,
                    label="Главная"
                ),
                ft.NavigationBarDestination(
                    icon=ft.Icons.INSERT_CHART,
                    selected_icon=ft.Icons.INSERT_CHART,
                    label="Отчеты"
                ),
                ft.NavigationBarDestination(
                    icon=ft.Icons.INFO,
                    selected_icon=ft.Icons.INFO,
                    label="О программе"
                ),
            ]
        )

        # Инициализация
        self.page.navigation_bar = self.nav_bar
        self.show_home_page()

    def show_home_page(self):
        """Показывает главную страницу"""
        self.page.controls.clear()

        # Заголовок
        header = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.SECURITY, size=32, color=ft.Colors.BLUE),
                    ft.Text("Mobile Guard", size=28, weight=ft.FontWeight.BOLD),
                ], alignment=ft.MainAxisAlignment.CENTER),
                ft.Text("Анализ безопасности Android приложений", size=16, color=ft.Colors.GREY_600),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.padding.only(bottom=20)
        )

        # Кнопка обновления
        refresh_btn = ft.ElevatedButton(
            "Обновить список APK",
            icon=ft.Icons.REFRESH,
            on_click=self.refresh_apk_list,
            style=ft.ButtonStyle(padding=15)
        )

        # Статистика
        stats_row = ft.Row([
            self.file_count_text,
            ft.Container(expand=True),
            refresh_btn
        ])

        # Контейнер для списка APK
        list_container = ft.Container(
            content=self.apk_list_view,
            expand=True,
            border=ft.border.all(1, ft.Colors.GREY_300),
            border_radius=10,
            padding=10
        )

        # Собираем страницу
        self.page.add(
            ft.Column([
                header,
                stats_row,
                self.status_text,
                list_container
            ], expand=True, spacing=15)
        )

        # Загружаем APK файлы
        self.load_apk_files()
        self.page.update()

    def load_apk_files(self):
        """Загружает и отображает APK файлы"""
        self.apk_list_view.controls.clear()

        try:
            apk_files = self.find_apk_files()
            
            # Обновляем метрики
            if PROMETHEUS_AVAILABLE:
                update_apk_files_count(len(apk_files))

            if not apk_files:
                self.apk_list_view.controls.append(
                    ft.Card(
                        content=ft.Container(
                            content=ft.Column([
                                ft.Icon(ft.Icons.WARNING_AMBER, size=48, color=ft.Colors.ORANGE),
                                ft.Text("APK файлы не найдены", size=18, weight=ft.FontWeight.BOLD),
                                ft.Text("Поместите APK файлы в одну из следующих папок:", size=14),
                                ft.Column([
                                    ft.Text(f"• {dir}", size=12, color=ft.Colors.GREY)
                                    for dir in self.download_dirs[:3]
                                ], spacing=5),
                                ft.ElevatedButton(
                                    "Создать демо-файлы",
                                    on_click=lambda e: self.create_demo_files_and_refresh()
                                )
                            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=15),
                            padding=40
                        )
                    )
                )
            else:
                for i, apk in enumerate(apk_files):
                    card = self.create_apk_card(apk, i)
                    self.apk_list_view.controls.append(card)

            self.file_count_text.value = f"Найдено APK файлов: {len(apk_files)}"
            self.status_text.value = ""

        except Exception as e:
            self.status_text.value = f"Ошибка загрузки файлов: {str(e)}"
            self.status_text.color = ft.Colors.RED

        self.page.update()

    def create_apk_card(self, apk_info, index):
        """Создает карточку для APK файла"""
        # Форматируем размер
        size_mb = apk_info["size"] / (1024 * 1024)
        size_str = f"{size_mb:.2f} MB"

        # Определяем уровень вредоносности
        maliciousness, color = self.determine_maliciousness(apk_info["name"])

        # Создаем карточку
        card = ft.Card(
            elevation=3,
            content=ft.Container(
                content=ft.Column([
                    # Заголовок
                    ft.Row([
                        self.get_android_icon(color),
                        ft.Column([
                            ft.Text(apk_info["name"],
                                    size=16,
                                    weight=ft.FontWeight.BOLD,
                                    overflow=ft.TextOverflow.ELLIPSIS),
                            ft.Text(apk_info["last_modified"],
                                    size=12,
                                    color=ft.Colors.GREY_600),
                        ], expand=True, spacing=0),
                        ft.Text(size_str, size=14, color=ft.Colors.GREY_600),
                    ]),

                    # Путь (усеченный)
                    ft.Text(
                        f"Путь: {apk_info['path'][:60]}..." if len(
                            apk_info['path']) > 60 else f"Путь: {apk_info['path']}",
                        size=12,
                        color=ft.Colors.GREY
                    ),

                    # Индикатор вредоносности
                    ft.Column([
                        self.get_maliciousness_text(maliciousness, color),
                        ft.Container(expand=True),
                        ft.Icon(ft.Icons.WARNING, color=color, size=22)
                        if maliciousness != "низкая" else ft.Container()
                    ]),

                    # Кнопки действий
                    ft.Row([
                        ft.ElevatedButton(
                            "Анализировать",
                            icon=ft.Icons.SEARCH,
                            on_click=lambda e, a=apk_info: self.analyze_apk_file(a),
                            width=150
                        ),
                        ft.OutlinedButton(
                            "Информация",
                            icon=ft.Icons.INFO,
                            on_click=lambda e, a=apk_info: self.show_apk_info(a),
                            width=160
                        ),
                        ft.Container(expand=True),
                        ft.IconButton(
                            icon=ft.Icons.DELETE,
                            icon_color=ft.Colors.RED,
                            tooltip="Удалить файл",
                            on_click=lambda e, idx=index, apk=apk_info: self.delete_apk_file(idx, apk)
                        )
                    ], spacing=10)
                ], spacing=10),
                padding=15,
                on_click=lambda e, a=apk_info: self.select_apk(a)
            )
        )

        return card

    def delete_apk_file(self, index, apk_info):
        """Удаляет APK файл с диска и из списка"""

        def confirm_delete(e):
            try:
                # Удаляем файл с диска
                file_path = apk_info["path"]
                if os.path.exists(file_path):
                    os.remove(file_path)
                    
                    # Обновляем метрики
                    if PROMETHEUS_AVAILABLE:
                        record_file_operation('delete')
                    
                    # Удаляем из списка
                    if index < len(self.apk_list_view.controls):
                        self.apk_list_view.controls.pop(index)

                    # Обновляем счетчик
                    current_count = len(self.apk_list_view.controls)
                    self.file_count_text.value = f"Найдено APK файлов: {current_count}"

                    self.page.close(dialog)
                    self.page.update()

                    # Показываем сообщение об успехе
                    self.show_message_dialog("Успех", f"Файл удален: {apk_info['name']}", "info")
                else:
                    self.page.close(dialog)
                    self.show_message_dialog("Ошибка", f"Файл не найден: {apk_info['name']}", "warning")

            except Exception as ex:
                self.page.close(dialog)
                self.show_message_dialog("Ошибка", f"Ошибка удаления: {str(ex)}", "error")

        def cancel_delete(e):
            self.page.close(dialog)

        # Диалог подтверждения удаления
        dialog = ft.AlertDialog(
            title=ft.Text("Подтверждение удаления", weight=ft.FontWeight.BOLD),
            content=ft.Column([
                ft.Text(f"Вы действительно хотите удалить файл?", size=14),
                ft.Text(f"'{apk_info['name']}'", size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.RED),
                ft.Text(f"Путь: {apk_info['path']}", size=12, color=ft.Colors.GREY_600),
                ft.Text("Это действие невозможно отменить!", size=12, color=ft.Colors.RED, italic=True)
            ], tight=True, spacing=10),
            actions=[
                ft.TextButton("Отмена", on_click=cancel_delete),
                ft.TextButton("Удалить", on_click=confirm_delete, style=ft.ButtonStyle(color=ft.Colors.RED))
            ],
            actions_alignment=ft.MainAxisAlignment.END
        )

        self.page.open(dialog)

    def analyze_apk_file(self, apk_info):
        """Запускает анализ APK файла"""
        self.status_text.value = f"Анализирую {apk_info['name']}..."
        self.status_text.color = ft.Colors.BLUE
        self.page.update()

        try:
            if APK_ANALYZER_AVAILABLE:
                # Записываем метрику начала анализа
                if PROMETHEUS_AVAILABLE:
                    record_file_operation('analysis_start')
                
                # Вызываем функцию анализа из модуля apk_analyzer
                results = analyze_single_apk(
                    apk_info['path'],
                    output_dir=os.path.join(os.path.dirname(__file__), "analysis_results")
                )

                if results:
                    # Обновляем метрики успешного анализа
                    if PROMETHEUS_AVAILABLE:
                        record_apk_analysis(status='success')
                        record_file_operation('analysis_complete')
                    
                    self.show_analysis_results(apk_info, results)
                else:
                    if PROMETHEUS_AVAILABLE:
                        record_apk_analysis(status='error')
                    
                    self.status_text.value = f"Не удалось проанализировать {apk_info['name']}"
                    self.status_text.color = ft.Colors.RED
            else:
                # Демо-режим
                self.show_demo_analysis(apk_info)

        except Exception as e:
            if PROMETHEUS_AVAILABLE:
                record_apk_analysis(status='error')
            
            self.status_text.value = f"Ошибка анализа: {str(e)}"
            self.status_text.color = ft.Colors.RED
            self.page.update()

    def show_analysis_results(self, apk_info, analysis_data):
        """Показывает результаты анализа с использованием нового модуля отчетов"""
        # Проверяем формат данных (старый или новый)
        if isinstance(analysis_data, dict) and 'structured_report' in analysis_data:
            # Новый формат с отчетом
            structured_report = analysis_data.get('structured_report', {})
            saved_files = analysis_data.get('saved_files', {})
            
            # Получаем данные из отчета
            permissions = structured_report.get('permissions', {}).get('list', [])
            security = structured_report.get('security_assessment', {})
            
            # Используем ReportComposer для предпросмотра
            if REPORT_COMPOSER_AVAILABLE:
                composer = ReportComposer()
                preview_column = composer.get_report_preview(structured_report)
            else:
                # Упрощенный предпросмотр
                maliciousness, color = self.determine_maliciousness(
                    apk_info['name'], 
                    permissions
                )
                preview_column = ft.Column([
                    ft.Row([
                        self.get_android_icon(color),
                        self.get_maliciousness_text(maliciousness, color),
                    ], spacing=10),
                    ft.Text(f"Разрешений: {len(permissions)}", size=14),
                ])
        else:
            # Старый формат данных
            permissions = analysis_data.get('Permissions', []) if isinstance(analysis_data, dict) else []
            saved_files = {}
            
            # Определяем уровень вредоносности
            maliciousness, color = self.determine_maliciousness(apk_info['name'], permissions)
            preview_column = ft.Column([
                ft.Row([
                    self.get_android_icon(color),
                    self.get_maliciousness_text(maliciousness, color),
                ], spacing=10),
                ft.Text(f"Разрешений: {len(permissions)}", size=14),
            ])

        # Создаем список разрешений
        permissions_list = ft.Column([
            ft.Text(f"{i + 1}. {perm}", size=14)
            for i, perm in enumerate(permissions[:15])  # Показываем первые 15
        ], scroll=ft.ScrollMode.AUTO, height=200)

        if len(permissions) > 15:
            permissions_list.controls.append(
                ft.Text(f"... и еще {len(permissions) - 15} разрешений",
                        size=12, color=ft.Colors.GREY)
            )

        # Создаем диалог
        dialog_content = [
            preview_column,
            ft.Divider(),
            ft.Text("Разрешения:", size=16, weight=ft.FontWeight.BOLD),
            permissions_list,
            ft.Text(f"Всего разрешений: {len(permissions)}", size=14),
        ]
        
        # Добавляем информацию о сохраненных файлах
        if saved_files:
            dialog_content.extend([
                ft.Divider(),
                ft.Text("Сохраненные отчеты:", size=16, weight=ft.FontWeight.BOLD),
                ft.Column([
                    ft.Text(f"• {os.path.basename(path)}", size=12, color=ft.Colors.GREEN)
                    for fmt, path in saved_files.items()
                ])
            ])

        actions = [
            ft.TextButton("Сохранить полный отчет",
                          on_click=lambda e: self.save_full_report(apk_info, analysis_data)),
            ft.TextButton("Закрыть", on_click=lambda e: self.page.close(dialog))
        ]

        dialog = ft.AlertDialog(
            title=ft.Text(f"Результаты анализа: {apk_info['name']}"),
            content=ft.Column(dialog_content, tight=True, spacing=10),
            actions=actions
        )

        self.page.open(dialog)
        self.status_text.value = f"Анализ завершен для {apk_info['name']}"
        self.status_text.color = ft.Colors.GREEN
        self.page.update()

    def save_full_report(self, apk_info, analysis_data):
        """Сохраняет полный отчет с использованием ReportComposer"""
        try:
            if REPORT_COMPOSER_AVAILABLE:
                # Создаем компоновщик отчетов
                composer = ReportComposer()
                
                # Подготавливаем данные
                if isinstance(analysis_data, dict) and 'structured_report' in analysis_data:
                    report = analysis_data['structured_report']
                else:
                    # Создаем новый отчет из старых данных
                    report = composer.compose_report(
                        apk_info,
                        analysis_data[0] if isinstance(analysis_data, list) else analysis_data
                    )
                
                # Сохраняем отчет
                apk_name = os.path.splitext(apk_info['name'])[0]
                saved_files = composer.save_report(
                    report=report,
                    apk_name=apk_name,
                    formats=['json', 'txt', 'csv', 'html']
                )
                
                # Записываем метрики генерации отчетов
                if PROMETHEUS_AVAILABLE:
                    for fmt in saved_files.keys():
                        record_report_generation(report_format=fmt)
                    record_file_operation('report_generation')
                
                # Показываем сообщение
                report_count = len(saved_files)
                
                # Открываем диалог с результатами сохранения
                if saved_files:
                    self.show_saved_reports_dialog(saved_files, f"Сохранено {report_count} отчетов")
                else:
                    self.show_message_dialog("Предупреждение", "Не удалось сохранить отчеты", "warning")
            else:
                # Старый метод сохранения
                self.save_analysis_report_old(apk_info, analysis_data)
                
        except Exception as e:
            self.show_message_dialog("Ошибка", f"Ошибка сохранения: {str(e)}", "error")

    def show_saved_reports_dialog(self, saved_files, success_message=""):
        """Показывает диалог с сохраненными отчетами"""
        report_list = ft.Column([
            ft.ListTile(
                leading=ft.Icon(ft.Icons.INSERT_DRIVE_FILE, color=ft.Colors.BLUE),
                title=ft.Text(os.path.basename(path)),
                subtitle=ft.Text(f"Формат: {fmt.upper()}"),
                on_click=lambda e, p=path: self.open_report_file(p)
            )
            for fmt, path in saved_files.items()
        ], height=300)

        dialog_content = [
            ft.Text("Сохраненные отчеты", size=18, weight=ft.FontWeight.BOLD),
        ]
        
        if success_message:
            dialog_content.append(
                ft.Text(success_message, size=14, color=ft.Colors.GREEN)
            )
            
        dialog_content.extend([
            ft.Divider(),
            report_list
        ])

        dialog = ft.AlertDialog(
            content=ft.Column(dialog_content, tight=True, spacing=10),
            actions=[
                ft.TextButton("Открыть папку", on_click=lambda e: self.open_reports_folder_dialog()),
                ft.TextButton("Закрыть", on_click=lambda e: self.page.close(dialog))
            ]
        )
        self.page.open(dialog)

    def open_report_file(self, file_path):
        """Открывает файл отчета"""
        self.show_file_content_dialog(file_path)

    def open_reports_folder_dialog(self):
        """Открывает диалог с информацией о папке отчетов"""
        reports_dir = os.path.join(os.path.dirname(__file__), "analysis_reports")
        if os.path.exists(reports_dir):
            self.show_message_dialog(
                "Папка отчетов", 
                f"Отчеты сохранены в папке:\n{reports_dir}",
                "info"
            )
        else:
            self.show_message_dialog(
                "Внимание", 
                "Папка отчетов не найдена. Создайте отчеты через анализ APK файлов.",
                "warning"
            )

    def save_analysis_report_old(self, apk_info, analysis_data):
        """Старый метод сохранения отчета (для обратной совместимости)"""
        try:
            # Создаем директорию для отчетов
            reports_dir = os.path.join(os.path.dirname(__file__), "reports")
            os.makedirs(reports_dir, exist_ok=True)

            # Сохраняем в JSON
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(reports_dir, f"{apk_info['name']}_{timestamp}.json")

            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_data, f, indent=4, ensure_ascii=False)

            self.show_message_dialog("Успех", f"Отчет сохранен:\n{report_file}", "info")

        except Exception as e:
            self.show_message_dialog("Ошибка", f"Ошибка сохранения: {str(e)}", "error")

    def show_demo_analysis(self, apk_info):
        """Показывает демо-результаты анализа"""
        # Демо-разрешения
        demo_permissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.READ_EXTERNAL_STORAGE"
        ]

        # Определяем уровень вредоносности
        maliciousness, color = self.determine_maliciousness(apk_info['name'], demo_permissions)

        dialog = ft.AlertDialog(
            title=ft.Text(f"Демо-анализ: {apk_info['name']}"),
            content=ft.Column([
                ft.Text("Внимание: Androguard не установлен!",
                        size=14, color=ft.Colors.RED, weight=ft.FontWeight.BOLD),
                ft.Text("Показаны демо-данные", size=12, color=ft.Colors.GREY),
                ft.Divider(),
                ft.Row([
                    self.get_android_icon(color),
                    self.get_maliciousness_text(maliciousness, color),
                ], spacing=10),
                ft.Text("Примерные разрешения:", size=14),
                ft.Column([
                    ft.Text("• android.permission.INTERNET"),
                    ft.Text("• android.permission.ACCESS_NETWORK_STATE"),
                    ft.Text("• android.permission.READ_EXTERNAL_STORAGE"),
                ])
            ], tight=True, spacing=10),
            actions=[
                ft.TextButton("Установить Androguard",
                              on_click=lambda e: self.install_androguard()),
                ft.TextButton("Закрыть", on_click=lambda e: self.page.close(dialog))
            ]
        )

        self.page.open(dialog)
        self.status_text.value = f"Демо-анализ завершен для {apk_info['name']}"
        self.status_text.color = ft.Colors.ORANGE
        self.page.update()

    def show_reports_page(self):
        """Показывает страницу с отчетами"""
        self.page.controls.clear()

        # Заголовок
        header = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.INSERT_CHART, size=32, color=ft.Colors.BLUE),
                    ft.Text("Отчеты анализа", size=28, weight=ft.FontWeight.BOLD),
                ], alignment=ft.MainAxisAlignment.CENTER),
                ft.Text("Просмотр сохраненных отчетов", size=16, color=ft.Colors.GREY_600),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.padding.only(bottom=20)
        )

        # Поиск отчетов
        reports = self.find_reports()
        
        if not reports:
            content = ft.Column([
                header,
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Icon(ft.Icons.INSERT_DRIVE_FILE, size=48, color=ft.Colors.GREY),
                            ft.Text("Отчеты не найдены", size=18, weight=ft.FontWeight.BOLD),
                            ft.Text("Проанализируйте APK файлы, чтобы создать отчеты", size=14),
                            ft.Text("Отчеты сохраняются в папке 'analysis_reports'", size=12, color=ft.Colors.GREY),
                        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=15),
                        padding=40
                    )
                )
            ], expand=True, spacing=20)
        else:
            # Список отчетов
            reports_list = ft.ListView(expand=True, spacing=10)
            
            for report in reports:
                reports_list.controls.append(self.create_report_card(report))
            
            content = ft.Column([
                header,
                ft.Text(f"Найдено отчетов: {len(reports)}", size=16),
                ft.ElevatedButton(
                    "Обновить список",
                    icon=ft.Icons.REFRESH,
                    on_click=lambda e: self.show_reports_page(),
                    width=200
                ),
                ft.Container(
                    content=reports_list,
                    expand=True,
                    border=ft.border.all(1, ft.Colors.GREY_300),
                    border_radius=10,
                    padding=10
                ),
            ], expand=True, spacing=15)

        self.page.add(content)
        self.page.update()

    def find_reports(self):
        """Находит все сохраненные отчеты"""
        reports_dir = os.path.join(os.path.dirname(__file__), "analysis_reports")
        
        if not os.path.exists(reports_dir):
            return []
            
        report_files = []
        
        for ext in ['.json', '.txt', '.csv', '.html']:
            for report_file in Path(reports_dir).rglob(f"*{ext}"):
                try:
                    report_info = {
                        "name": report_file.name,
                        "path": str(report_file),
                        "size": report_file.stat().st_size,
                        "modified": datetime.fromtimestamp(report_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "format": ext[1:]  # Без точки
                    }
                    report_files.append(report_info)
                except Exception as e:
                    print(f"Ошибка чтения отчета {report_file}: {e}")
                    continue
                    
        # Сортируем по дате изменения (новые сначала)
        report_files.sort(key=lambda x: x['modified'], reverse=True)
        return report_files[:50]  # Ограничиваем 50 отчетами

    def create_report_card(self, report_info):
        """Создает карточку для отчета"""
        # Форматируем размер
        size_kb = report_info["size"] / 1024
        size_str = f"{size_kb:.1f} KB"
        
        # Иконка в зависимости от формата
        format_icons = {
            'json': ft.Icons.CODE,
            'txt': ft.Icons.TEXT_FIELDS,
            'csv': ft.Icons.TABLE_CHART,
            'html': ft.Icons.HTML
        }
        icon = format_icons.get(report_info['format'], ft.Icons.INSERT_DRIVE_FILE)
        
        # Цвет в зависимости от формата
        format_colors = {
            'json': ft.Colors.GREEN,
            'txt': ft.Colors.BLUE,
            'csv': ft.Colors.ORANGE,
            'html': ft.Colors.RED
        }
        color = format_colors.get(report_info['format'], ft.Colors.GREY)

        card = ft.Card(
            elevation=2,
            content=ft.Container(
                content=ft.Column([
                    # Заголовок
                    ft.Row([
                        ft.Icon(icon, color=color, size=24),
                        ft.Column([
                            ft.Text(report_info["name"],
                                    size=14,
                                    weight=ft.FontWeight.BOLD,
                                    overflow=ft.TextOverflow.ELLIPSIS),
                            ft.Text(f"Формат: {report_info['format'].upper()}", 
                                    size=12, color=ft.Colors.GREY_600),
                        ], expand=True, spacing=0),
                        ft.Text(size_str, size=12, color=ft.Colors.GREY_600),
                    ]),
                    
                    # Информация
                    ft.Text(f"Изменен: {report_info['modified']}", size=12, color=ft.Colors.GREY),
                    
                    # Кнопки действий
                    ft.Row([
                        ft.OutlinedButton(
                            "Просмотреть",
                            icon=ft.Icons.VISIBILITY,
                            on_click=lambda e, r=report_info: self.view_report(r),
                            width=160
                        ),
                        ft.OutlinedButton(
                            "Удалить",
                            icon=ft.Icons.DELETE,
                            icon_color=ft.Colors.RED,
                            on_click=lambda e, r=report_info: self.delete_report(r),
                            width=160
                        ),
                        ft.Container(expand=True),
                    ], spacing=5)
                ], spacing=10),
                padding=15
            )
        )
        
        return card

    def view_report(self, report_info):
        """Просматривает отчет"""
        self.show_file_content_dialog(report_info['path'])

    def delete_report(self, report_info):
        """Удаляет отчет"""

        def confirm_delete(e):
            try:
                file_path = report_info["path"]
                if os.path.exists(file_path):
                    os.remove(file_path)
                    
                    # Обновляем метрики
                    if PROMETHEUS_AVAILABLE:
                        record_file_operation('report_delete')
                    
                    # Обновляем страницу отчетов
                    self.page.close(dialog)
                    self.show_reports_page()
                    
                    self.show_message_dialog("Успех", f"Отчет удален: {report_info['name']}", "info")
                else:
                    self.page.close(dialog)
                    self.show_message_dialog("Ошибка", "Файл не найден", "warning")
                    
            except Exception as ex:
                self.page.close(dialog)
                self.show_message_dialog("Ошибка", f"Ошибка удаления: {str(ex)}", "error")

        def cancel_delete(e):
            self.page.close(dialog)

        # Диалог подтверждения
        dialog = ft.AlertDialog(
            title=ft.Text("Подтверждение удаления"),
            content=ft.Column([
                ft.Text(f"Удалить отчет?", size=14),
                ft.Text(f"'{report_info['name']}'", size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.RED),
                ft.Text(f"Формат: {report_info['format']}", size=12),
            ], tight=True, spacing=10),
            actions=[
                ft.TextButton("Отмена", on_click=cancel_delete),
                ft.TextButton("Удалить", on_click=confirm_delete, style=ft.ButtonStyle(color=ft.Colors.RED))
            ]
        )
        self.page.open(dialog)

    def show_file_content_dialog(self, file_path):
        """Показывает содержимое файла в диалоговом окне"""
        try:
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_name)[1].lower()
            
            if file_ext in ['.txt', '.json', '.csv']:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Ограничиваем длину для больших файлов
                max_chars = 5000
                if len(content) > max_chars:
                    display_content = content[:max_chars] + f"\n\n... (файл слишком большой, показаны первые {max_chars} символов из {len(content)})"
                    show_full = True
                else:
                    display_content = content
                    show_full = False
                
                # Определяем шрифт в зависимости от формата
                font_family = "monospace" if file_ext in ['.txt', '.json'] else None
                
                dialog = ft.AlertDialog(
                    title=ft.Text(f"Просмотр файла: {file_name}"),
                    content=ft.Container(
                        content=ft.Column([
                            ft.Text(f"Путь: {file_path}", size=12, color=ft.Colors.GREY),
                            ft.Divider(),
                            ft.Text(display_content, 
                                   size=12, 
                                   font_family=font_family,
                                   selectable=True),
                        ], scroll=ft.ScrollMode.AUTO),
                        width=600,
                        height=500
                    ),
                    actions=[
                        ft.TextButton("Закрыть", on_click=lambda e: self.page.close(dialog))
                    ] + ([ft.TextButton("Показать полностью", 
                                        on_click=lambda e: self.show_full_file_content(file_path))] 
                         if show_full else [])
                )
                self.page.open(dialog)
                
            elif file_ext == '.html':
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Для HTML файлов показываем информацию о файле
                dialog = ft.AlertDialog(
                    title=ft.Text(f"HTML отчет: {file_name}"),
                    content=ft.Column([
                        ft.Text("Это HTML файл. Для просмотра:", size=14),
                        ft.Text(f"1. Откройте файл в браузере", size=12),
                        ft.Text(f"2. Или откройте в текстовом редакторе", size=12),
                        ft.Divider(),
                        ft.Text(f"Путь к файлу:", size=12, weight=ft.FontWeight.BOLD),
                        ft.Text(file_path, size=12, selectable=True, font_family="monospace"),
                    ], tight=True, spacing=10),
                    actions=[
                        ft.TextButton("Закрыть", on_click=lambda e: self.page.close(dialog))
                    ]
                )
                self.page.open(dialog)
                
            else:
                self.show_message_dialog("Предупреждение", 
                                       f"Формат файла {file_ext} не поддерживается для просмотра.", 
                                       "warning")
                
        except Exception as e:
            self.show_message_dialog("Ошибка", f"Не удалось открыть файл: {str(e)}", "error")

    def show_full_file_content(self, file_path):
        """Показывает полное содержимое файла"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_name)[1].lower()
            font_family = "monospace" if file_ext in ['.txt', '.json'] else None
            
            dialog = ft.AlertDialog(
                title=ft.Text(f"Полное содержимое: {file_name}"),
                content=ft.Container(
                    content=ft.Column([
                        ft.Text(f"Размер файла: {len(content)} символов", size=12, color=ft.Colors.GREY),
                        ft.Divider(),
                        ft.Text(content, 
                               size=10,  # Уменьшаем размер шрифта для больших файлов
                               font_family=font_family,
                               selectable=True),
                    ], scroll=ft.ScrollMode.AUTO),
                    width=700,
                    height=600
                ),
                actions=[
                    ft.TextButton("Закрыть", on_click=lambda e: self.page.close(dialog))
                ]
            )
            self.page.open(dialog)
            
        except Exception as e:
            self.show_message_dialog("Ошибка", f"Не удалось прочитать файл: {str(e)}", "error")

    def show_message_dialog(self, title, message, message_type="info"):
        """Показывает диалоговое окно с сообщением"""
        colors = {
            "info": ft.Colors.BLUE,
            "warning": ft.Colors.ORANGE,
            "error": ft.Colors.RED,
            "success": ft.Colors.GREEN
        }
        
        icons = {
            "info": ft.Icons.INFO,
            "warning": ft.Icons.WARNING,
            "error": ft.Icons.ERROR,
            "success": ft.Icons.CHECK_CIRCLE
        }
        
        color = colors.get(message_type, ft.Colors.BLUE)
        icon = icons.get(message_type, ft.Icons.INFO)
        
        dialog = ft.AlertDialog(
            title=ft.Row([
                ft.Icon(icon, color=color),
                ft.Text(title, weight=ft.FontWeight.BOLD),
            ]),
            content=ft.Text(message, size=14),
            actions=[
                ft.TextButton("OK", on_click=lambda e: self.page.close(dialog))
            ]
        )
        self.page.open(dialog)

    def install_androguard(self):
        """Показывает инструкцию по установке Androguard"""
        dialog = ft.AlertDialog(
            title=ft.Text("Установка Androguard"),
            content=ft.Column([
                ft.Text("Для полноценного анализа установите Androguard:", size=14),
                ft.Divider(),
                ft.Text("Через pip:", size=12, weight=ft.FontWeight.BOLD),
                ft.Text("pip install androguard",
                        selectable=True,
                        font_family="monospace",
                        bgcolor=ft.Colors.BLACK12,
                        padding=5),
                ft.Text("Через Termux на Android:", size=12, weight=ft.FontWeight.BOLD),
                ft.Text("pkg install python\npip install androguard",
                        selectable=True,
                        font_family="monospace",
                        bgcolor=ft.Colors.BLACK12,
                        padding=5),
                ft.Text("После установки перезапустите приложение", size=12, color=ft.Colors.BLUE)
            ], tight=True, spacing=10),
            actions=[
                ft.TextButton("Закрыть", on_click=lambda e: self.page.close(dialog))
            ]
        )
        self.page.open(dialog)

    def show_apk_info(self, apk_info):
        """Показывает информацию о APK файле"""
        dialog = ft.AlertDialog(
            title=ft.Text("Информация о APK"),
            content=ft.Column([
                ft.Row([
                    self.get_android_icon(ft.Colors.BLUE),
                    ft.Text(apk_info["name"], weight=ft.FontWeight.BOLD, size=18),
                ], spacing=10),
                ft.Divider(),
                ft.Text(f"Путь: {apk_info['path']}", size=14),
                ft.Text(f"Размер: {apk_info['size'] / (1024 * 1024):.2f} MB", size=14),
                ft.Text(f"Изменен: {apk_info['last_modified']}", size=14),
            ], tight=True, spacing=10),
            actions=[
                ft.TextButton("Анализировать",
                              on_click=lambda e, a=apk_info: self.analyze_apk_file(a)),
                ft.TextButton("Закрыть", on_click=lambda e: self.page.close(dialog))
            ]
        )
        self.page.open(dialog)

    def select_apk(self, apk_info):
        """Обрабатывает выбор APK файла"""
        # Просто показываем информацию без всплывающего уведомления
        pass

    def refresh_apk_list(self, e):
        """Обновляет список APK файлов"""
        self.load_apk_files()

    def create_demo_files_and_refresh(self, e=None):
        """Создает демо-файлы и обновляет список"""
        self.create_demo_files()
        self.load_apk_files()
        self.show_message_dialog("Успех", "Демо-файлы созданы", "success")

    def change_page(self, e):
        """Переключает страницы"""
        if e.control.selected_index == 0:
            self.show_home_page()
        elif e.control.selected_index == 1:
            self.show_reports_page()
        elif e.control.selected_index == 2:
            self.show_about_page()

    def show_about_page(self):
        """Показывает страницу 'О программе'"""
        self.page.controls.clear()

        content = ft.Column([
            ft.Text("О программе", size=28, weight=ft.FontWeight.BOLD),
            ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Divider(),
                        ft.ListTile(
                            leading=ft.Icon(ft.Icons.DESCRIPTION),
                            title=ft.Text("Описание"),
                            subtitle=ft.Text(
                                "Мобильное приложение для анализа безопасности APK файлов. "
                                "Обнаруживает подозрительные разрешения и оценивает уровень риска."
                            )
                        ),
                        ft.ListTile(
                            leading=ft.Icon(ft.Icons.SECURITY),
                            title=ft.Text("Безопасность"),
                            subtitle=ft.Text(
                                "• Анализ разрешений Android\n"
                                "• Первичная и вторичная оценка вредоносности APK-файлов\n"
                                "• Поиск опасных разрешений\n"
                                "• Цветовая индикация рисков\n"
                                "• Генерация отчетов"
                            )
                        ),
                        ft.ListTile(
                            leading=ft.Icon(ft.Icons.INSERT_CHART),
                            title=ft.Text("Отчеты"),
                            subtitle=ft.Text(
                                "• JSON, TXT, CSV, HTML форматы\n"
                                "• Подробная статистика\n"
                                "• Рекомендации по безопасности\n"
                                "• Предпросмотр отчетов"
                            )
                        ),
                    ], spacing=0),
                    padding=10
                )
            ),
        ], scroll=ft.ScrollMode.AUTO, spacing=20)

        self.page.add(content)
        self.page.update()


def main(page: ft.Page):
    app = APKAnalyzerApp(page)