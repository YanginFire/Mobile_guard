import json
import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import flet as ft


class ReportComposer:
    """Класс для создания и управления отчетами анализа APK"""
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Инициализация компоновщика отчетов
        
        Args:
            output_dir: Директория для сохранения отчетов (если None, используется текущая)
        """
        self.output_dir = output_dir or os.getcwd()
        self.reports_dir = os.path.join(self.output_dir, "analysis_reports")
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Форматы отчетов
        self.supported_formats = ['json', 'csv', 'txt', 'html']
        
        # Подозрительные слова для оценки
        self.suspicious_keywords = [
            "hack", "crack", "mod", "premium", "free", "cheat",
            "virus", "trojan", "malware", "spyware", "keylogger",
            "bot", "exploit", "root", "jailbreak", "adware", "ransomware"
        ]
        
        # Опасные разрешения
        self.dangerous_permissions = [
            "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS",
            "WRITE_CONTACTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG", "WRITE_CALL_LOG"
        ]

    def compose_report(self, apk_info: Dict, analysis_data: Dict) -> Dict[str, Any]:
        """
        Создает структурированный отчет на основе данных анализа
        
        Args:
            apk_info: Информация о APK файле
            analysis_data: Данные анализа из androguard
            
        Returns:
            Словарь с полным отчетом
        """
        try:
            # Базовый отчет
            report = {
                'metadata': {
                    'apk_name': apk_info.get('name', 'Unknown'),
                    'apk_path': apk_info.get('path', ''),
                    'file_size': apk_info.get('size', 0),
                    'last_modified': apk_info.get('last_modified', ''),
                    'analysis_date': datetime.now().isoformat(),
                    'report_version': '1.0'
                },
                'permissions': {
                    'total': len(analysis_data.get('Permissions', [])),
                    'list': analysis_data.get('Permissions', []),
                    'dangerous': self._extract_dangerous_permissions(analysis_data.get('Permissions', []))
                },
                'intents': analysis_data.get('Intents', {}),
                'security_assessment': self._assess_security(apk_info, analysis_data),
                'recommendations': [],
                'statistics': {
                    'total_permissions': len(analysis_data.get('Permissions', [])),
                    'dangerous_permissions': len(self._extract_dangerous_permissions(analysis_data.get('Permissions', []))),
                    'activities': len(analysis_data.get('Intents', {})),
                    'suspicious_score': self._calculate_suspicious_score(apk_info, analysis_data)
                }
            }
            
            # Добавляем рекомендации
            report['recommendations'] = self._generate_recommendations(report)
            
            return report
            
        except Exception as e:
            print(f"Ошибка при составлении отчета: {e}")
            return {}

    def _extract_dangerous_permissions(self, permissions: List[str]) -> List[str]:
        """Извлекает опасные разрешения из списка"""
        dangerous = []
        for perm in permissions:
            for danger_perm in self.dangerous_permissions:
                if danger_perm.lower() in perm.lower():
                    dangerous.append(perm)
                    break
        return dangerous

    def _calculate_suspicious_score(self, apk_info: Dict, analysis_data: Dict) -> int:
        """Вычисляет оценку подозрительности"""
        score = 0
        
        # Проверка имени файла
        apk_name_lower = apk_info.get('name', '').lower()
        for keyword in self.suspicious_keywords:
            if keyword in apk_name_lower:
                score += 1
                
        # Проверка разрешений
        permissions = analysis_data.get('Permissions', [])
        dangerous_perms = self._extract_dangerous_permissions(permissions)
        score += len(dangerous_perms) * 0.5
        
        # Нормализуем оценку (0-10)
        return min(int(score * 2), 10)

    def _assess_security(self, apk_info: Dict, analysis_data: Dict) -> Dict[str, Any]:
        """Оценивает безопасность APK"""
        permissions = analysis_data.get('Permissions', [])
        dangerous_perms = self._extract_dangerous_permissions(permissions)
        suspicious_score = self._calculate_suspicious_score(apk_info, analysis_data)
        
        # Определяем уровень риска
        if suspicious_score >= 7 or len(dangerous_perms) >= 3:
            risk_level = "высокий"
            risk_color = ft.Colors.RED
        elif suspicious_score >= 4 or len(dangerous_perms) >= 1:
            risk_level = "средний"
            risk_color = ft.Colors.ORANGE
        else:
            risk_level = "низкий"
            risk_color = ft.Colors.GREEN
            
        return {
            'risk_level': risk_level,
            'risk_color': risk_color,
            'suspicious_score': suspicious_score,
            'dangerous_permissions_count': len(dangerous_perms),
            'warnings': self._generate_warnings(apk_info, analysis_data)
        }

    def _generate_warnings(self, apk_info: Dict, analysis_data: Dict) -> List[str]:
        """Генерирует предупреждения на основе анализа"""
        warnings = []
        permissions = analysis_data.get('Permissions', [])
        
        # Проверка опасных разрешений
        dangerous_perms = self._extract_dangerous_permissions(permissions)
        if dangerous_perms:
            warnings.append(f"Обнаружено {len(dangerous_perms)} опасных разрешений")
            
        # Проверка подозрительного имени
        apk_name_lower = apk_info.get('name', '').lower()
        for keyword in self.suspicious_keywords:
            if keyword in apk_name_lower:
                warnings.append(f"Подозрительное ключевое слово в имени: '{keyword}'")
                break
                
        # Проверка количества разрешений
        if len(permissions) > 20:
            warnings.append(f"Большое количество разрешений: {len(permissions)}")
            
        return warnings

    def _generate_recommendations(self, report: Dict) -> List[str]:
        """Генерирует рекомендации на основе отчета"""
        recommendations = []
        security = report.get('security_assessment', {})
        
        if security.get('risk_level') == "высокий":
            recommendations.append("⚠️ НЕ УСТАНАВЛИВАТЬ! Файл выглядит подозрительно")
            recommendations.append("Проверьте APK через VirusTotal или другие антивирусы")
            
        if security.get('dangerous_permissions_count', 0) > 0:
            recommendations.append(f"Внимание! Приложение запрашивает {security['dangerous_permissions_count']} опасных разрешений")
            recommendations.append("Подумайте, действительно ли приложению нужны эти разрешения")
            
        if len(report.get('permissions', {}).get('list', [])) > 25:
            recommendations.append("Приложение запрашивает слишком много разрешений")
            recommendations.append("Рассмотрите альтернативные приложения с меньшим количеством разрешений")
            
        if not recommendations:
            recommendations.append("Проверка через Angroguard не обнаружила угроз")
            
        return recommendations

    def save_report(self, report: Dict, apk_name: str, formats: List[str] = None) -> Dict[str, str]:
        """
        Сохраняет отчет в указанных форматах
        
        Args:
            report: Структурированный отчет
            apk_name: Имя APK файла (без расширения)
            formats: Список форматов для сохранения ['json', 'csv', 'txt', 'html']
            
        Returns:
            Словарь с путями к сохраненным файлам
        """
        if formats is None:
            formats = ['json', 'txt']
            
        saved_files = {}
        
        # Создаем уникальное имя файла с timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{apk_name}_{timestamp}"
        
        for fmt in formats:
            if fmt not in self.supported_formats:
                print(f"Формат {fmt} не поддерживается. Пропускаем...")
                continue
                
            file_path = os.path.join(self.reports_dir, f"{base_filename}.{fmt}")
            
            try:
                if fmt == 'json':
                    self._save_json(report, file_path)
                    saved_files['json'] = file_path
                    
                elif fmt == 'csv':
                    self._save_csv(report, file_path)
                    saved_files['csv'] = file_path
                    
                elif fmt == 'txt':
                    self._save_txt(report, file_path)
                    saved_files['txt'] = file_path
                    
                elif fmt == 'html':
                    self._save_html(report, file_path)
                    saved_files['html'] = file_path
                    
            except Exception as e:
                print(f"Ошибка сохранения отчета в формате {fmt}: {e}")
                
        return saved_files

    def _save_json(self, report: Dict, file_path: str):
        """Сохраняет отчет в JSON формате"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

    def _save_csv(self, report: Dict, file_path: str):
        """Сохраняет отчет в CSV формате"""
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Метаданные
            writer.writerow(['Метаданные'])
            metadata = report.get('metadata', {})
            for key, value in metadata.items():
                writer.writerow([key, str(value)])
                
            writer.writerow([])
            
            # Разрешения
            writer.writerow(['Разрешения'])
            permissions = report.get('permissions', {}).get('list', [])
            writer.writerow(['Общее количество', len(permissions)])
            writer.writerow(['Список разрешений'])
            for perm in permissions:
                writer.writerow([perm])
                
            writer.writerow([])
            
            # Оценка безопасности
            writer.writerow(['Оценка безопасности'])
            security = report.get('security_assessment', {})
            for key, value in security.items():
                if key != 'risk_color':
                    writer.writerow([key, str(value)])
                    
            writer.writerow([])
            
            # Рекомендации
            writer.writerow(['Рекомендации'])
            for rec in report.get('recommendations', []):
                writer.writerow([rec])

    def _save_txt(self, report: Dict, file_path: str):
        """Сохраняет отчет в текстовом формате"""
        with open(file_path, 'w', encoding='utf-8') as f:
            # Заголовок
            f.write("=" * 60 + "\n")
            f.write(f"ОТЧЕТ АНАЛИЗА БЕЗОПАСНОСТИ APK\n")
            f.write("=" * 60 + "\n\n")
            
            # Метаданные
            f.write("МЕТАДАННЫЕ:\n")
            f.write("-" * 40 + "\n")
            metadata = report.get('metadata', {})
            for key, value in metadata.items():
                if key != 'report_version':
                    f.write(f"  {key}: {value}\n")
                    
            f.write("\n")
            
            # Разрешения
            permissions = report.get('permissions', {})
            f.write(f"РАЗРЕШЕНИЯ: {permissions.get('total', 0)} всего\n")
            f.write("-" * 40 + "\n")
            
            dangerous = permissions.get('dangerous', [])
            if dangerous:
                f.write(f"⚠️  ОПАСНЫЕ РАЗРЕШЕНИЯ ({len(dangerous)}):\n")
                for perm in dangerous:
                    f.write(f"  • {perm}\n")
                f.write("\n")
                
            all_perms = permissions.get('list', [])
            f.write(f"ВСЕ РАЗРЕШЕНИЯ:\n")
            for i, perm in enumerate(all_perms, 1):
                f.write(f"  {i:2d}. {perm}\n")
                
            f.write("\n")
            
            # Оценка безопасности
            security = report.get('security_assessment', {})
            f.write(f"ОЦЕНКА БЕЗОПАСНОСТИ:\n")
            f.write("-" * 40 + "\n")
            f.write(f"  Уровень риска: {security.get('risk_level', 'неизвестно')}\n")
            f.write(f"  Оценка подозрительности: {security.get('suspicious_score', 0)}/10\n")
            
            warnings = security.get('warnings', [])
            if warnings:
                f.write(f"  Предупреждения:\n")
                for warning in warnings:
                    f.write(f"    ⚠ {warning}\n")
                    
            f.write("\n")
            
            # Рекомендации
            f.write("РЕКОМЕНДАЦИИ:\n")
            f.write("-" * 40 + "\n")
            for rec in report.get('recommendations', []):
                f.write(f"  • {rec}\n")
                
            f.write("\n")
            
            # Статистика
            stats = report.get('statistics', {})
            f.write("СТАТИСТИКА:\n")
            f.write("-" * 40 + "\n")
            f.write(f"  Всего разрешений: {stats.get('total_permissions', 0)}\n")
            f.write(f"  Опасных разрешений: {stats.get('dangerous_permissions', 0)}\n")
            f.write(f"  Активностей: {stats.get('activities', 0)}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write(f"Отчет сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n")

    def _save_html(self, report: Dict, file_path: str):
        """Сохраняет отчет в HTML формате (упрощенный)"""
        html_content = f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Отчет анализа APK: {report.get('metadata', {}).get('apk_name', 'Unknown')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; }}
                .dangerous {{ color: red; font-weight: bold; }}
                .warning {{ color: orange; }}
                .safe {{ color: green; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Отчет анализа безопасности APK</h1>
                <p>Файл: {report.get('metadata', {}).get('apk_name', 'Unknown')}</p>
                <p>Дата анализа: {report.get('metadata', {}).get('analysis_date', 'Unknown')}</p>
            </div>
            
            <div class="section">
                <h2>Оценка безопасности</h2>
                <p><strong>Уровень риска:</strong> 
                    <span class="{report.get('security_assessment', {}).get('risk_level', '').lower()}">
                        {report.get('security_assessment', {}).get('risk_level', 'неизвестно')}
                    </span>
                </p>
            </div>
            
            <div class="section">
                <h2>Разрешения ({report.get('permissions', {}).get('total', 0)})</h2>
                <ul>
        """
        
        # Добавляем разрешения
        for perm in report.get('permissions', {}).get('list', []):
            is_dangerous = any(danger_perm.lower() in perm.lower() 
                             for danger_perm in self.dangerous_permissions)
            danger_class = 'dangerous' if is_dangerous else ''
            html_content += f'<li class="{danger_class}">{perm}</li>\n'
            
        html_content += """
                </ul>
            </div>
            
            <div class="section">
                <h2>Рекомендации</h2>
                <ul>
        """
        
        # Добавляем рекомендации
        for rec in report.get('recommendations', []):
            html_content += f'<li>{rec}</li>\n'
            
        html_content += """
                </ul>
            </div>
            
            <div class="section">
                <p><em>Отчет сгенерирован автоматически</em></p>
            </div>
        </body>
        </html>
        """
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def get_report_preview(self, report: Dict) -> ft.Column:
        """
        Создает предварительный просмотр отчета для Flet UI
        
        Args:
            report: Структурированный отчет
            
        Returns:
            ft.Column с элементами предпросмотра
        """
        security = report.get('security_assessment', {})
        permissions = report.get('permissions', {})
        
        # Цвет для уровня риска
        risk_color = security.get('risk_color', ft.Colors.BLACK)
        
        return ft.Column([
            ft.Text("Предпросмотр отчета", size=18, weight=ft.FontWeight.BOLD),
            ft.Divider(),
            
            ft.Row([
                ft.Icon(ft.Icons.SECURITY, color=risk_color),
                ft.Text(f"Уровень риска: {security.get('risk_level', 'неизвестно')}", 
                       size=16, weight=ft.FontWeight.BOLD, color=risk_color),
            ]),
            
            ft.Text(f"Оценка подозрительности: {security.get('suspicious_score', 0)}/10", size=14),
            ft.Text(f"Разрешений: {permissions.get('total', 0)} (опасных: {len(permissions.get('dangerous', []))})", size=14),
            
            # Предупреждения
            ft.Container(
                content=ft.Column([
                    ft.Text("Предупреждения:", size=14, weight=ft.FontWeight.BOLD),
                    ft.Column([
                        ft.Text(f"• {warning}", size=12)
                        for warning in security.get('warnings', [])[:3]
                    ])
                ], spacing=5),
                bgcolor=ft.Colors.YELLOW_100 if security.get('warnings') else ft.Colors.TRANSPARENT,
                padding=10,
                border_radius=5
            ),
            
            # Рекомендации
            ft.Container(
                content=ft.Column([
                    ft.Text("Рекомендации:", size=14, weight=ft.FontWeight.BOLD),
                    ft.Column([
                        ft.Text(f"• {rec}", size=12)
                        for rec in report.get('recommendations', [])[:3]
                    ])
                ], spacing=5),
                bgcolor=ft.Colors.BLUE_50,
                padding=10,
                border_radius=5
            ),
        ], spacing=10)


# Функции для обратной совместимости
def save_to_json(data, output_file):
    """Сохраняет данные в JSON файл"""
    composer = ReportComposer()
    return composer._save_json(data, output_file)


def save_to_csv(data, output_file):
    """Сохраняет данные в CSV файл"""
    composer = ReportComposer()
    
    if isinstance(data, list) and len(data) > 0:
        report = composer.compose_report(
            {'name': data[0].get('APK', 'Unknown')},
            data[0]
        )
        return composer._save_csv(report, output_file)
    return composer._save_csv({}, output_file)