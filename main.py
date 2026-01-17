import flet as ft
from interface import main as app_main
import threading
import time
import socket

def is_port_open(port, host='0.0.0.0', timeout=5):
    """Проверяет, открыт ли порт"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def start_metrics():
    """Запускает сервер метрик в отдельном потоке"""
    try:
        from prometheus import start_metrics_server
        print("Запуск сервера метрик Prometheus...")
        metrics_thread = start_metrics_server(8001)
        print(f"Сервер метрик Prometheus запущен на порту 8001")
        
        max_wait = 30
        for i in range(max_wait):
            if is_port_open(8001, '0.0.0.0', 1):
                print(f"Порт 8001 успешно открыт")
                return metrics_thread
            print(f"Ожидание открытия порта 8001... ({i+1}/{max_wait})")
            time.sleep(1)
        
        print("Предупреждение: порт 8001 не открылся вовремя")
        return metrics_thread
        
    except Exception as e:
        print(f"Ошибка запуска сервера метрик: {e}")
        try:
            from prometheus_client import start_http_server
            print("Запуск сервера метрик через prometheus_client напрямую...")
            start_http_server(8001)
            print(f"Сервер метрик запущен на порту 8001")
            return True
        except Exception as e2:
            print(f"Не удалось запустить сервер метрик: {e2}")
        return None

if __name__ == "__main__":
    # Запускаем сервер метрик в отдельном потоке
    print("=" * 60)
    print("Запуск Mobile Guard APK Analyzer")
    print("=" * 60)
    
    metrics_thread = start_metrics()
    
    time.sleep(2)
    
    print("Запуск Flet приложения...")
    print(f"Приложение доступно по адресу: http://localhost:8000")
    print(f"Метрики доступны по адресу: http://localhost:8001/metrics")
    print("=" * 60)
    
    # Запуск Flet приложения
    ft.app(
        target=app_main,
        view=ft.AppView.WEB_BROWSER,
        assets_dir="assets",
        port=8000,
        host="0.0.0.0"
    )