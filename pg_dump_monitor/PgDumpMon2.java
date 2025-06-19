Для решения проблемы ложных срабатываний, связанных с постоянным I/O в кластере Patroni, можно реализовать следующие улучшения:

### 1. **Добавление доверенных процессов в белый список**
   - Включить `/usr/pgsql-16/bin/postgres` и другие штатные процессы PostgreSQL в белый список. Процессы из этого списка будут игнорироваться при мониторинге.
   - Пример реализации:
     ```java
     private final Set<String> trustedProcesses = Set.of(
         "/usr/pgsql-16/bin/postgres",
         "patroni",
         "haproxy"
     );

     private boolean isTrustedProcess(ProcessInfo process) {
         return trustedProcesses.stream()
             .anyMatch(trusted -> process.getCommand() != null && process.getCommand().contains(trusted));
     }
     ```
     В методе `scanProcesses()` можно добавить проверку:
     ```java
     if (isTrustedProcess(process)) {
         return; // Пропускаем доверенные процессы
     }
     ```

### 2. **Фильтрация по пользователю**
   - Штатные процессы PostgreSQL обычно работают от пользователя `postgres`. Можно добавить проверку:
     ```java
     private boolean isPostgresUser(ProcessInfo process) {
         return "postgres".equals(process.getUser());
     }
     ```
     Исключать такие процессы из мониторинга или снижать их подозрительность.

### 3. **Анализ временных меток и паттернов I/O**
   - **Продолжительность операции**: Дамп обычно завершается быстро (секунды/минуты), тогда как штатный I/O длится постоянно.
   - **Паттерны записи**: Дамп создает файлы с расширениями `.sql`, `.dump`, а штатный I/O работает с WAL-логами и данными БД.
   - Пример проверки:
     ```java
     private boolean isLikelyDumpActivity(ProcessInfo process) {
         return process.getOutputFiles().keySet().stream()
             .anyMatch(file -> file.endsWith(".sql") || file.endsWith(".dump"));
     }
     ```

### 4. **Учет размера данных**
   - Если дамп весит 25 МБ, а штатный I/O достигает 100 МБ/с, можно установить порог подозрительности для размера файлов выше 25 МБ:
     ```java
     private static final long DUMP_SIZE_THRESHOLD = 30 * 1024 * 1024; // 30 МБ
     if (process.getTotalIOBytes() > DUMP_SIZE_THRESHOLD) {
         // Считаем подозрительным
     }
     ```

### 5. **Интеграция с Patroni API**
   - Запрашивать статус кластера через Patroni API. Если процесс является частью штатной работы Patroni (например, репликация), игнорировать его.

### 6. **Улучшенная логика оценки подозрительности**
   - В методе `isSuspiciousProcess` снизить вес I/O-активности и увеличить вес других факторов (аргументы командной строки, подключения к PostgreSQL):
     ```java
     // Было: 20% за I/O, 30% за подключения
     // Стало: 10% за I/O, 40% за подключения
     if (process.getPostgreSQLConnections() > 0) {
         suspicionScore += 40; // Увеличиваем вес подключений
     }
     if (process.getTotalIOBytes() > SUSPICIOUS_DATA_THRESHOLD) {
         suspicionScore += 10; // Уменьшаем вес I/O
     }
     ```

### Пример итогового исправления
Добавьте в класс `PgDumpProcessMonitor`:
```java
private final Set<String> trustedProcesses = Set.of(
    "/usr/pgsql-16/bin/postgres",
    "patroni",
    "haproxy",
    "postgres:"
);

private boolean isTrustedProcess(ProcessInfo process) {
    return process.getCommand() != null && 
           trustedProcesses.stream().anyMatch(process.getCommand()::contains);
}

private void scanProcesses() {
    try {
        List<ProcessInfo> currentProcesses = getCurrentProcesses();
        for (ProcessInfo process : currentProcesses) {
            if (isTrustedProcess(process)) {
                continue; // Пропускаем доверенные процессы
            }
            // Остальная логика...
        }
    } catch (Exception e) {
        logger.error("Error during process scanning: " + e.getMessage(), e);
    }
}
```

### Вывод
- **Доверенные процессы**: Игнорировать `/usr/pgsql-16/bin/postgres` и другие штатные процессы.
- **Фильтрация по пользователю**: Исключать процессы от `postgres`.
- **Уточнение логики I/O**: Учитывать временные метки, размер данных и паттерны записи.
- **Настройка весов**: Снизить влияние I/O на общий score подозрительности.

Это минимизирует ложные срабатывания без ущерба для детектирования реальных дампов.
