# Анализ проблемы с обнаружением pg_dump

Код не реагирует на команду `pg_dump -h srv1.company.com -p 5432 -U postgres -d myschema -f ./test5.sql` по нескольким причинам:

## Основные проблемы

1. **Паттерны для аргументов не охватывают все варианты**:
   - Нет паттерна для параметра `-f` (output file)
   - Проверка хоста не учитывает доменные имена (только IP-адреса)

2. **Проверка сетевых подключений**:
   - Код проверяет только IP-адреса, но не доменные имена
   - Не учитывается, что процесс может подключаться к PostgreSQL через доменное имя

3. **Проверка файловых операций**:
   - Недостаточно строгая проверка выходных файлов

## Исправленное решение

Вот основные изменения, которые нужно внести:

### 1. Обновление паттернов аргументов

```java
private final List<Pattern> pgDumpArgumentPatterns = Arrays.asList(
    Pattern.compile("pg_dump", Pattern.CASE_INSENSITIVE),
    Pattern.compile("--host\\s+[\\w\\.\\-]+", Pattern.CASE_INSENSITIVE), // добавлены буквы и дефисы
    Pattern.compile("--port\\s+\\d+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("--username\\s+\\w+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("--dbname\\s+\\w+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("--format\\s+(custom|tar|plain)", Pattern.CASE_INSENSITIVE),
    Pattern.compile("-h\\s+[\\w\\.\\-]+", Pattern.CASE_INSENSITIVE), // добавлены буквы и дефисы
    Pattern.compile("-p\\s+\\d+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("-U\\s+\\w+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("-d\\s+\\w+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("--file\\s+\\S+", Pattern.CASE_INSENSITIVE), // добавлен параметр --file
    Pattern.compile("-f\\s+\\S+", Pattern.CASE_INSENSITIVE) // добавлен параметр -f
);
```

### 2. Обновление метода isPostgreSQLConnection

```java
private boolean isPostgreSQLConnection(NetworkConnection conn) {
    // Проверяем стандартные порты PostgreSQL
    if (conn.getRemotePort() == POSTGRESQL_DEFAULT_PORT || 
        conn.getRemotePort() == 5000 || // HAProxy write
        conn.getRemotePort() == 5001) { // HAProxy read
        return true;
    }
    
    // Проверяем известные хосты PostgreSQL (теперь включая домены)
    String remoteAddr = conn.getRemoteAddress();
    return postgresqlHosts.contains(remoteAddr) || 
           remoteAddr.endsWith(".company.com"); // или другой домен вашей организации
}
```

### 3. Улучшение проверки файловых операций

```java
private boolean isDumpFile(String filename) {
    if (filename == null) return false;
    String lower = filename.toLowerCase();
    return lower.endsWith(".sql") || 
           lower.endsWith(".dump") || 
           lower.endsWith(".backup") || 
           lower.endsWith(".bak") ||
           lower.contains("dump") ||
           lower.contains("backup") ||
           (filename.contains("pg_dump") && filename.endsWith(".out")) ||
           (filename.startsWith("./") && (filename.endsWith(".sql") || filename.endsWith(".dump")));
}
```

### 4. Добавление проверки DNS-имен в анализ сетевых подключений

```java
private void analyzeProcessNetworkConnections(ProcessInfo process) {
    try {
        List<NetworkConnection> connections = getProcessNetworkConnections(process.getPid());
        
        for (NetworkConnection conn : connections) {
            // Проверяем подключения к PostgreSQL портам
            if (isPostgreSQLConnection(conn)) {
                process.incrementPostgreSQLConnections();
                process.addNetworkConnection(conn);
                
                // Дополнительная проверка DNS имени
                if (conn.getRemoteAddress() != null && !conn.getRemoteAddress().matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                    // Это доменное имя, а не IP - увеличиваем подозрительность
                    process.setSuspicionScore(process.getSuspicionScore() + 5);
                }
                
                logger.debug("Found PostgreSQL connection for PID " + process.getPid() + 
                           ": " + conn.getRemoteAddress() + ":" + conn.getRemotePort());
            }
        }
    } catch (Exception e) {
        logger.debug("Error analyzing network connections for PID " + process.getPid() + ": " + e.getMessage());
    }
}
```

### 5. Обновление метода isSuspiciousProcess

```java
private boolean isSuspiciousProcess(ProcessInfo process) {
    int suspicionScore = 0;
    List<String> reasons = new ArrayList<>();
    
    // 1. Проверка паттернов аргументов pg_dump (вес: 40%)
    if (process.getPgDumpPatternScore() >= 3) {
        suspicionScore += 40;
        reasons.add("High pg_dump argument pattern match (" + process.getPgDumpPatternScore() + " patterns)");
    } else if (process.getPgDumpPatternScore() >= 2) {
        // Даже если совпадений меньше, но есть ключевые параметры
        if (process.getArguments() != null && 
            (process.getArguments().contains("-h") || process.getArguments().contains("--host")) &&
            (process.getArguments().contains("-p") || process.getArguments().contains("--port"))) {
            suspicionScore += 30;
            reasons.add("Key pg_dump parameters detected");
        }
    }
    
    // 2. Подключения к PostgreSQL (вес: 30%)
    if (process.getPostgreSQLConnections() > 0) {
        suspicionScore += 30;
        reasons.add("PostgreSQL database connections (" + process.getPostgreSQLConnections() + " connections)");
    }
    
    // 3. Большие файловые операции (вес: 20%)
    if (process.getTotalIOBytes() > SUSPICIOUS_DATA_THRESHOLD) {
        suspicionScore += 20;
        reasons.add("Large file I/O operations (" + formatBytes(process.getTotalIOBytes()) + ")");
    }
    
    // 4. Создание файлов дампов (вес: 10%)
    if (process.getDumpFileCount() > 0) {
        suspicionScore += 10;
        reasons.add("Creating dump-like files (" + process.getDumpFileCount() + " files)");
    }
    
    // Дополнительные проверки для команд с выходным файлом
    if (process.getArguments() != null && 
        (process.getArguments().contains("-f") || process.getArguments().contains("--file"))) {
        suspicionScore += 10;
        reasons.add("Output to file specified in arguments");
    }
    
    process.setSuspicionReasons(reasons);
    process.setSuspicionScore(suspicionScore);
    
    return suspicionScore >= 50;
}
```

## Дополнительные рекомендации

1. **Логирование полной команды процесса**:
   ```java
   logger.debug("Analyzed process: PID=" + process.getPid() + 
               ", Pattern Score=" + patternMatches + 
               ", Command=" + process.getCommand() + 
               ", Args=" + process.getArguments());
   ```

2. **Добавление проверки доменных имен в список postgresqlHosts**:
   ```java
   postgresqlHosts.add("srv1.company.com");
   postgresqlHosts.add("srv2.company.com");
   // и другие серверы PostgreSQL в вашей организации
   ```

3. **Улучшение обработки аргументов командной строки**:
   - Можно добавить парсинг аргументов в более структурированный формат
   - Учитывать, что параметры могут быть объединены (например, `-Upostgres`)

Эти изменения должны значительно улучшить детектирование команд pg_dump, включая случаи с доменными именами и различными комбинациями параметров.
