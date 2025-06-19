Смотря на ваш код, я вижу проблему, которая может вызывать "пропадание" метрики в VictoriaMetrics. Проблема связана с **race condition** и **двойной отправкой метрик**.

## Анализ проблемы:

В методе `checkNetworkConnections()` у вас происходит следующее:

```java
// ВАЖНО: сначала устанавливаем alertActive = true
alertActive = true;

sendAlert(pid, command, line);

// Теперь отправляем метрики с alertActive = true
sendMetrics();

return true;
```

А в методе `scanProcesses()`:

```java
// Если состояние алерта изменилось, немедленно отправляем метрики
if (alertActive != previousAlertState) {
    log("INFO", "Alert state changed...");
    sendMetrics(); // ← Вторая отправка!
}
```

## Проблемы:

1. **Двойная отправка метрик**: Когда обнаруживается алерт, метрики отправляются дважды почти одновременно - один раз из `checkNetworkConnections()` и второй раз из `scanProcesses()`.

2. **Race condition**: У вас есть два потока (`ScheduledExecutorService` с 2 потоками), которые могут одновременно вызывать `sendMetrics()`.

3. **Перезапись данных**: VictoriaMetrics может интерпретировать быстро следующие друг за другом записи с одинаковыми метками как перезапись предыдущих значений.

## Решение:

Уберите дублирование отправки метрик:

```java
private boolean checkNetworkConnections(String pid, String command) {
    try {
        Process proc = Runtime.getRuntime().exec("netstat -anp | grep " + pid);
        
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("ESTABLISHED")) {
                    for (int port : MONITORED_PORTS) {
                        if (line.contains(":" + port)) {
                            sendAlert(pid, command, line);
                            return true; // Убираем все отправки метрик отсюда
                        }
                    }
                }
            }
        }
    } catch (Exception e) {
        log("ERROR", "Error checking network connections for PID " + pid + ": " + e.getMessage());
    }
    return false;
}
```

И оставьте только одну отправку в `scanProcesses()`:

```java
private void scanProcesses() {
    try {
        Process proc = Runtime.getRuntime().exec("ps -eo pid,cmd --no-headers");
        
        boolean currentScanAlert = false;
        boolean previousAlertState = alertActive;
        
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                for (String pgDumpPath : PG_DUMP_PATHS) {
                    if (line.contains(pgDumpPath)) {
                        String pid = line.trim().split("\\s+")[0];
                        if (checkNetworkConnections(pid, line)) {
                            currentScanAlert = true;
                        }
                        break;
                    }
                }
            }
        }
        
        alertActive = currentScanAlert;
        
        // Отправляем метрики только при изменении состояния
        if (alertActive != previousAlertState) {
            log("INFO", "Alert state changed from " + previousAlertState + " to " + alertActive);
            // Небольшая задержка для избежания race condition
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            sendMetrics();
        }
        
    } catch (Exception e) {
        log("ERROR", "Error scanning processes: " + e.getMessage());
    }
}
```

Также рекомендую использовать один поток для мониторинга вместо двух:

```java
private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
```

Это должно решить проблему с "пропаданием" метрики в VictoriaMetrics.
