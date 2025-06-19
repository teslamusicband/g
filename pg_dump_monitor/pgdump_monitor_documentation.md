# PgDump Process Monitor

## Описание

PgDump Process Monitor - это система мониторинга безопасности, предназначенная для обнаружения несанкционированного использования утилиты `pg_dump` для извлечения данных из PostgreSQL баз данных. Программа непрерывно сканирует системные процессы и отслеживает сетевые соединения, отправляя алерты при обнаружении подозрительной активности.

## Архитектура системы

### Компоненты архитектуры

```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│   Процессы ОС       │    │  PgDump Monitor      │    │  VictoriaMetrics    │
│                     │    │                      │    │                     │
│ ┌─────────────────┐ │    │ ┌──────────────────┐ │    │ ┌─────────────────┐ │
│ │   pg_dump       │ │◄───┤ │ Process Scanner  │ │    │ │   HTTP API      │ │
│ └─────────────────┘ │    │ └──────────────────┘ │    │ └─────────────────┘ │
│                     │    │ ┌──────────────────┐ │    │                     │
│ ┌─────────────────┐ │    │ │ Network Monitor  │ │    │                     │
│ │ Сетевые соедин. │ │◄───┤ └──────────────────┘ │    │                     │
│ └─────────────────┘ │    │ ┌──────────────────┐ │    │                     │
│                     │    │ │ Alert Manager    │ │────┼────────────────────►│
└─────────────────────┘    │ └──────────────────┘ │    └─────────────────────┘
                           │ ┌──────────────────┐ │
                           │ │ Metrics Sender   │ │
                           │ └──────────────────┘ │
                           └──────────────────────┘
```

### Основные модули

#### 1. Process Scanner
- **Назначение**: Сканирование системных процессов
- **Метод**: Выполнение команды `ps -eo pid,cmd --no-headers`
- **Частота**: Каждые 1000 мс
- **Цель**: Обнаружение процессов pg_dump по известным путям

#### 2. Network Monitor  
- **Назначение**: Анализ сетевых соединений
- **Метод**: Выполнение команды `netstat -anp | grep <PID>`
- **Триггер**: При обнаружении процесса pg_dump
- **Цель**: Проверка активных соединений на мониторируемых портах

#### 3. Alert Manager
- **Назначение**: Генерация и логирование алертов
- **Формат**: Структурированное сообщение с деталями процесса
- **Выход**: Консольный лог с меткой времени

#### 4. Metrics Sender
- **Назначение**: Отправка метрик в систему мониторинга
- **Протокол**: HTTP POST в формате Prometheus
- **Назначение**: VictoriaMetrics API

## Конфигурация

### Константы конфигурации

| Параметр | Значение | Описание |
|----------|----------|-----------|
| `PG_DUMP_PATHS` | `/usr/pgsql-16/bin/pg_dump`, `pg_dump`, `/bin/pg_dump`, `/etc/alternative/pgsql-pg_dump` | Пути поиска pg_dump |
| `MONITORED_PORTS` | `5000`, `5432` | Мониторируемые порты |
| `MONITORING_INTERVAL` | `1000 мс` | Интервал сканирования |
| `VICTORIA_METRICS_URL` | `http://srv1.company.com:8428/api/v1/import/prometheus` | URL для отправки метрик |

### Настройка окружения

Перед запуском убедитесь, что:
- Java Runtime Environment установлена (версия 8+)
- Система имеет доступ к командам `ps` и `netstat`
- Сетевой доступ к серверу VictoriaMetrics

## Установка и запуск

### Компиляция

```bash
javac -d . com/security/pgdump/monitor/PgDumpProcessMonitor.java
```

### Создание JAR файла

```bash
jar cvfe pgdump-monitor.jar com.security.pgdump.monitor.PgDumpProcessMonitor com/
```

### Запуск приложения

#### Интерактивный режим
```bash
java com.security.pgdump.monitor.PgDumpProcessMonitor
```

#### Запуск из JAR
```bash
java -jar pgdump-monitor.jar
```

#### Фоновый режим (рекомендуется)
```bash
nohup java -jar pgdump-monitor.jar > pgdump-monitor.log 2>&1 &
```

### Системный сервис (systemd)

Создайте файл `/etc/systemd/system/pgdump-monitor.service`:

```ini
[Unit]
Description=PgDump Process Monitor
After=network.target

[Service]
Type=simple
User=monitor
WorkingDirectory=/opt/pgdump-monitor
ExecStart=/usr/bin/java -jar /opt/pgdump-monitor/pgdump-monitor.jar
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Активация сервиса:
```bash
sudo systemctl daemon-reload
sudo systemctl enable pgdump-monitor.service
sudo systemctl start pgdump-monitor.service
```

## Мониторинг и логи

### Формат логов

```
[YYYY-MM-DD HH:MM:SS] [LEVEL] MESSAGE
```

Примеры:
```
[2025-06-20 10:30:15] [INFO] Starting pg_dump monitoring on host: server01
[2025-06-20 10:35:22] [ALERT] 🚨 ALERT: pg_dump detected!
PID: 12345
Command: /usr/pgsql-16/bin/pg_dump -h database.company.com -U user dbname
Connection: tcp 0 0 192.168.1.100:54321 192.168.1.200:5432 ESTABLISHED 12345/pg_dump
Time: 2025-06-20 10:35:22
```

### Метрики VictoriaMetrics

Отправляемая метрика:
```
pg_dump_monitor_alert_active{host="hostname"} 1 timestamp
```

### Проверка статуса

```bash
# Проверка работы сервиса
sudo systemctl status pgdump-monitor.service

# Просмотр логов
sudo journalctl -u pgdump-monitor.service -f

# Проверка процесса
ps aux | grep PgDumpProcessMonitor
```

## Безопасность и ограничения

### Права доступа
- Программа требует права на выполнение команд `ps` и `netstat`
- Рекомендуется запуск под отдельным пользователем с минимальными привилегиями
- Не требует root доступа

### Производительность
- Минимальное влияние на систему (один запрос `ps` в секунду)
- Сетевые проверки выполняются только при обнаружении pg_dump
- Асинхронная отправка метрик

### Ограничения обнаружения
- Обнаруживает только процессы с известными именами/путями pg_dump
- Может пропустить переименованные или скомпилированные версии
- Не анализирует содержимое передаваемых данных

## Устранение неполадок

### Частые проблемы

#### 1. Ошибка подключения к VictoriaMetrics
```
[ERROR] Failed to send metrics. Response code: 500
```
**Решение**: Проверьте доступность сервера и правильность URL

#### 2. Ошибки выполнения системных команд
```
[ERROR] Error scanning processes: Cannot run program "ps"
```
**Решение**: Убедитесь, что команды `ps` и `netstat` доступны в PATH

#### 3. Ложные срабатывания
**Решение**: Настройте список мониторируемых портов в соответствии с вашей инфраструктурой

### Отладка

Для детальной отладки добавьте дополнительное логирование:
```bash
java -Djava.util.logging.config.file=logging.properties -jar pgdump-monitor.jar
```

## Интеграция с системами мониторинга

### Grafana Dashboard
Создайте дашборд для визуализации метрик:
- График активности алертов по времени
- Список хостов с активными алертами
- Статистика обнаруженных процессов

### Alertmanager
Настройте правила для уведомлений:
```yaml
- alert: PgDumpDetected
  expr: pg_dump_monitor_alert_active > 0
  labels:
    severity: critical
  annotations:
    summary: "Unauthorized pg_dump detected on {{ $labels.host }}"
```

## Поддержка и развитие

### Планы развития
- Поддержка конфигурационных файлов
- Интеграция с системами оповещений (Slack, email)
- Расширенный анализ сетевого трафика
- Поддержка других утилит резервного копирования

### Требования к системе
- **ОС**: Linux (протестировано на CentOS, Ubuntu)
- **Java**: версия 8 и выше
- **RAM**: минимум 64MB
- **CPU**: минимальные требования