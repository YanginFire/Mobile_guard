FROM python:3.9-slim

WORKDIR /app

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    curl \
    net-tools && \
    rm -rf /var/lib/apt/lists/*

# Копируем и устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY . .

# Создаем директории для данных
RUN mkdir -p analysis_reports downloads_test

# Открываем порты
EXPOSE 8000 8001

# Запускаем только main.py - он запустит и метрики и Flet
CMD ["python", "main.py"]