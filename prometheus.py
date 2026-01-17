from prometheus_client import start_http_server, Counter, Histogram, Gauge, Summary
import time
import threading
import os
from datetime import datetime
import sys
import psutil


# Добавляем путь для импорта
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Создаем метрики для дальнейшего их импорта в Grafana
APK_ANALYSIS_COUNT = Counter(
    'apk_analysis_total',
    'Total number of APK analyses performed',
    ['status']
)

APK_DETECTION_COUNT = Counter(
    'apk_detection_total',
    'Total number of APK detections by risk level',
    ['risk_level']  # Метка для уровня риска
)

APK_ANALYSIS_DURATION = Histogram(
    'apk_analysis_duration_seconds',
    'Duration of APK analysis in seconds',
    buckets=[0.1, 0.5, 1, 2, 5, 10, 30]
)

REPORT_GENERATION_COUNT = Counter(
    'report_generation_total',
    'Total number of reports generated',
    ['format']  # Метка для формата отчета
)

FILE_OPERATIONS_COUNT = Counter(
    'file_operations_total',
    'Total number of file operations',
    ['operation']  # Метка для типа операции
)

ACTIVE_USERS_GAUGE = Gauge(
    'active_users',
    'Number of active users'
)

APK_SCAN_TIME = Summary(
    'apk_scan_time_seconds',
    'Time spent scanning APK files'
)

# Дополнительные метрики для мониторинга системы
APK_FILES_COUNT = Gauge(
    'apk_files_total',
    'Total number of APK files found'
)

DANGEROUS_PERMISSIONS_COUNT = Gauge(
    'dangerous_permissions_detected',
    'Number of dangerous permissions detected in current scan'
)

# Функции для обновления метрик
def record_apk_analysis(status='success'):
    """Записывает факт анализа APK"""
    APK_ANALYSIS_COUNT.labels(status=status).inc()

def record_apk_detection(risk_level='low'):
    """Записывает обнаружение APK по уровню риска"""
    APK_DETECTION_COUNT.labels(risk_level=risk_level).inc()

def record_analysis_duration(duration):
    """Записывает длительность анализа"""
    APK_ANALYSIS_DURATION.observe(duration)

def record_report_generation(report_format='json'):
    """Записывает генерацию отчета"""
    REPORT_GENERATION_COUNT.labels(format=report_format).inc()

def record_file_operation(operation):
    """Записывает операцию с файлом"""
    FILE_OPERATIONS_COUNT.labels(operation=operation).inc()

def update_active_users(count):
    """Обновляет количество активных пользователей"""
    ACTIVE_USERS_GAUGE.set(count)

def update_apk_files_count(count):
    """Обновляет количество найденных APK файлов"""
    APK_FILES_COUNT.set(count)

def update_dangerous_permissions_count(count):
    """Обновляет количество опасных разрешений"""
    DANGEROUS_PERMISSIONS_COUNT.set(count)


# Мониторинг использования памяти и CPU
def start_system_metrics_monitor():
    """Мониторинг системных метрик"""
    
    # Создаем метрики для системы
    cpu_usage = Gauge('system_cpu_usage_percent', 'CPU usage percentage')
    memory_usage = Gauge('system_memory_usage_percent', 'Memory usage percentage')
    disk_usage = Gauge('system_disk_usage_percent', 'Disk usage percentage')
    
    def monitor():
        while True:
            try:
                # CPU
                cpu_usage.set(psutil.cpu_percent())
                
                # Memory
                memory = psutil.virtual_memory()
                memory_usage.set(memory.percent)
                
                # Disk
                disk = psutil.disk_usage('/')
                disk_usage.set(disk.percent)
                
            except Exception as e:
                print(f"Error monitoring system metrics: {e}")
            
            time.sleep(15)  # Обновляем каждые 15 секунд
    
    # Запускаем мониторинг в отдельном потоке
    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()

# Функция для запуска сервера метрик в отдельном потоке
def start_metrics_server(port=8001):
    """Запускает сервер метрик Prometheus в отдельном потоке"""
    def run_server():
        try:
            start_http_server(port)
            print(f"Prometheus metrics server started on port {port}")
            
            try:
                start_system_metrics_monitor()
            except ImportError:
                print("psutil not installed. System metrics monitoring disabled.")
                
            while True:
                time.sleep(60)
        except Exception as e:
            print(f"Failed to start metrics server: {e}")
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    return server_thread

# Декоратор для измерения времени выполнения функций
def track_duration(metric_name):
    """Декоратор для измерения времени выполнения функций"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Записываем в соответствующую метрику
                if metric_name == 'analysis':
                    record_analysis_duration(duration)
                elif metric_name == 'scan':
                    pass
                
                return result
            except Exception as e:
                # Записываем ошибку в метрики
                record_apk_analysis(status='error')
                raise e
        
        return wrapper
    return decorator


@track_duration('analysis')
def analyze_apk_with_metrics(apk_path):
    """Функция анализа APK с метриками"""
    record_apk_analysis(status='success')
    return {}

def main():
    """Главная функция для запуска сервера метрик"""
    # Запускаем сервер метрик в отдельном потоке
    metrics_thread = start_metrics_server(8001)
    print("Prometheus metrics server is running on http://localhost:8001")
    
    print("Monitoring the following metrics:")
    print("- APK analysis counts")
    print("- Risk level detections")
    print("- Report generation")
    print("- File operations")
    print("- System metrics (CPU, Memory, Disk)")
    
    # Держим основной поток активным
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping metrics server...")

if __name__ == "__main__":
    # Для отладки - запуск сервера метрик
    print("Starting metrics server in standalone mode...")
    start_metrics_server(8001)
    
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("Stopping metrics server...")