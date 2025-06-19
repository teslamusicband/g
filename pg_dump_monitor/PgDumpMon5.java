Проанализировав код, нашел несколько проблем, из-за которых алерт не срабатывает при команде `pg_dump -h srv1.company.com -p 5432 -U postgres -d myschema -f ./test5.sql`:

## Проблема 1: Низкий порог срабатывания в `isSuspiciousProcess()`

В методе `isSuspiciousProcess()` замените условие:

```java
if (process.getPgDumpPatternScore() >= 3) {
    suspicionScore += 40;
    reasons.add("High pg_dump argument pattern match (" + process.getPgDumpPatternScore() + " patterns)");
} else if (process.getPgDumpPatternScore() >= 2) {
    if (process.getArguments() != null && 
        (process.getArguments().contains("-h") || process.getArguments().contains("--host")) && 
        (process.getArguments().contains("-p") || process.getArguments().contains("--port"))) {
        suspicionScore += 30;
        reasons.add("Key pg_dump parameters detected");
    }
}
```

На:

```java
if (process.getPgDumpPatternScore() >= 5) {
    suspicionScore += 40;
    reasons.add("High pg_dump argument pattern match (" + process.getPgDumpPatternScore() + " patterns)");
} else if (process.getPgDumpPatternScore() >= 3) {
    if (process.getArguments() != null && 
        (process.getArguments().contains("-h") || process.getArguments().contains("--host")) && 
        (process.getArguments().contains("-p") || process.getArguments().contains("--port"))) {
        suspicionScore += 35;
        reasons.add("Key pg_dump parameters detected");
    }
} else if (process.getPgDumpPatternScore() >= 2) {
    suspicionScore += 25;
    reasons.add("Medium pg_dump argument pattern match (" + process.getPgDumpPatternScore() + " patterns)");
}
```

## Проблема 2: Неточное определение PostgreSQL соединений

В методе `isPostgreSQLConnection()` добавьте дополнительную проверку:

```java
private boolean isPostgreSQLConnection(NetworkConnection conn) {
    if (conn.getRemotePort() == POSTGRESQL_DEFAULT_PORT || conn.getRemotePort() == 5000 || conn.getRemotePort() == 5001) {
        return true;
    }
    String remoteAddr = conn.getRemoteAddress();
    return postgresqlHosts.contains(remoteAddr) || 
           remoteAddr.endsWith(".company.com") ||
           remoteAddr.equals("srv1.company.com");
}
```

## Проблема 3: Добавление детектирования файлового вывода

В методе `isSuspiciousProcess()` после проверки дампов файлов добавьте:

```java
if (process.getArguments() != null && 
    (process.getArguments().contains("-f ") || process.getArguments().contains("--file"))) {
    suspicionScore += 15;
    reasons.add("Output to file specified in arguments");
}

// Дополнительная проверка для файлов .sql
if (process.getArguments() != null && process.getArguments().contains(".sql")) {
    suspicionScore += 10;
    reasons.add("SQL file output detected");
}
```

## Проблема 4: Улучшение паттернов регулярных выражений

В конструкторе замените список `pgDumpArgumentPatterns`:

```java
private final List<Pattern> pgDumpArgumentPatterns = Arrays.asList(
    Pattern.compile("pg_dump", Pattern.CASE_INSENSITIVE),
    Pattern.compile("-h\\s+[\\w\\.\\-]+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("--host[\\s=]+[\\w\\.\\-]+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("-p\\s+\\d+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("--port[\\s=]+\\d+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("-U\\s+\\w+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("--username[\\s=]+\\w+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("-d\\s+\\w+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("--dbname[\\s=]+\\w+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("-f\\s+\\S+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("--file[\\s=]+\\S+", Pattern.CASE_INSENSITIVE),
    Pattern.compile("\\.sql", Pattern.CASE_INSENSITIVE)
);
```

## Проблема 5: Понижение порога алерта

Измените константу в начале класса:

```java
private static final int SUSPICION_THRESHOLD = 40; // было 50
```

Эти изменения должны решить проблему с детектированием вашей команды pg_dump.
