package com.security.pgdump.monitor;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import com.sun.management.OperatingSystemMXBean;
import java.lang.management.ManagementFactory;

/**
 * PostgreSQL pg_dump Process Behavior Monitor
 * Обнаруживает процессы pg_dump по поведенческим паттернам, а не по имени
 */
public class PgDumpProcessMonitor {
    
    private static final int POSTGRESQL_DEFAULT_PORT = 5432;
    private static final long SUSPICIOUS_DATA_THRESHOLD = 50 * 1024 * 1024; // 50MB
    private static final long MONITORING_INTERVAL = 5000; // 5 секунд
    private static final int NETWORK_TIMEOUT = 3000; // 3 секунды
    
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(3);
    private final Map<String, ProcessInfo> monitoredProcesses = new ConcurrentHashMap<>();
    private final Set<String> postgresqlHosts = new HashSet<>();
    private final SecurityLogger logger = new SecurityLogger();
    
    // Паттерны для обнаружения pg_dump
    private final List<Pattern> pgDumpArgumentPatterns = Arrays.asList(
        Pattern.compile("--host\\s+[\\d\\.]+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("--port\\s+\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("--username\\s+\\w+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("--dbname\\s+\\w+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("--format\\s+(custom|tar|plain)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("-h\\s+[\\d\\.]+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("-p\\s+\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("-U\\s+\\w+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("-d\\s+\\w+", Pattern.CASE_INSENSITIVE)
    );
    
    public PgDumpProcessMonitor() {
        // Добавляем известные хосты PostgreSQL
        postgresqlHosts.add("10.0.1.10"); // patroni-01
        postgresqlHosts.add("10.0.1.11"); // patroni-02  
        postgresqlHosts.add("10.0.1.12"); // patroni-03
        postgresqlHosts.add("10.0.1.5");  // HAProxy
        postgresqlHosts.add("localhost");
        postgresqlHosts.add("127.0.0.1");
    }
    
    /**
     * Основной метод запуска мониторинга
     */
    public void startMonitoring() {
        logger.info("Starting PostgreSQL pg_dump behavior monitoring...");
        
        // Запуск основного цикла мониторинга процессов
        scheduler.scheduleAtFixedRate(this::scanProcesses, 0, MONITORING_INTERVAL, TimeUnit.MILLISECONDS);
        
        // Запуск анализа сетевых подключений
        scheduler.scheduleAtFixedRate(this::analyzeNetworkConnections, 2000, MONITORING_INTERVAL, TimeUnit.MILLISECONDS);
        
        // Запуск анализа файловых операций
        scheduler.scheduleAtFixedRate(this::analyzeIOActivity, 3000, MONITORING_INTERVAL, TimeUnit.MILLISECONDS);
        
        logger.info("Process behavior monitoring started successfully");
    }
    
    /**
     * Сканирование всех процессов в системе
     */
    private void scanProcesses() {
        try {
            List<ProcessInfo> currentProcesses = getCurrentProcesses();
            
            for (ProcessInfo process : currentProcesses) {
                String processKey = process.getPid() + ":" + process.getStartTime();
                
                if (!monitoredProcesses.containsKey(processKey)) {
                    // Новый процесс - начинаем мониторинг
                    monitoredProcesses.put(processKey, process);
                    analyzeProcessBehavior(process);
                } else {
                    // Обновляем информацию о существующем процессе
                    ProcessInfo existing = monitoredProcesses.get(processKey);
                    updateProcessInfo(existing, process);
                    
                    if (isSuspiciousProcess(existing)) {
                        handleSuspiciousProcess(existing);
                    }
                }
            }
            
            // Удаляем завершившиеся процессы
            cleanupFinishedProcesses(currentProcesses);
            
        } catch (Exception e) {
            logger.error("Error during process scanning: " + e.getMessage(), e);
        }
    }
    
    /**
     * Получение списка текущих процессов
     */
    private List<ProcessInfo> getCurrentProcesses() {
        List<ProcessInfo> processes = new ArrayList<>();
        
        try {
            // Используем ProcessHandle API (Java 9+)
            ProcessHandle.allProcesses().forEach(ph -> {
                try {
                    ProcessHandle.Info info = ph.info();
                    if (info.command().isPresent()) {
                        ProcessInfo procInfo = new ProcessInfo();
                        procInfo.setPid(String.valueOf(ph.pid()));
                        procInfo.setCommand(info.command().get());
                        procInfo.setArguments(String.join(" ", info.arguments().orElse(new String[0])));
                        procInfo.setStartTime(info.startInstant().orElse(null));
                        procInfo.setUser(info.user().orElse("unknown"));
                        
                        processes.add(procInfo);
                    }
                } catch (Exception e) {
                    // Игнорируем ошибки доступа к отдельным процессам
                }
            });
            
        } catch (Exception e) {
            logger.error("Error getting process list: " + e.getMessage(), e);
            // Fallback к использованию системных команд
            processes = getProcessesFromSystem();
        }
        
        return processes;
    }
    
    /**
     * Альтернативный способ получения процессов через системные команды
     */
    private List<ProcessInfo> getProcessesFromSystem() {
        List<ProcessInfo> processes = new ArrayList<>();
        
        try {
            String os = System.getProperty("os.name").toLowerCase();
            Process proc;
            
            if (os.contains("linux")) {
                proc = Runtime.getRuntime().exec("ps -eo pid,user,lstart,cmd --no-headers");
            } else if (os.contains("windows")) {
                proc = Runtime.getRuntime().exec("wmic process get ProcessId,CommandLine,CreationDate /format:csv");
            } else {
                proc = Runtime.getRuntime().exec("ps -eo pid,user,lstart,command");
            }
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    ProcessInfo procInfo = parseProcessLine(line, os);
                    if (procInfo != null) {
                        processes.add(procInfo);
                    }
                }
            }
            
        } catch (Exception e) {
            logger.error("Error executing system command: " + e.getMessage(), e);
        }
        
        return processes;
    }
    
    /**
     * Парсинг строки с информацией о процессе
     */
    private ProcessInfo parseProcessLine(String line, String os) {
        try {
            ProcessInfo info = new ProcessInfo();
            
            if (os.contains("linux")) {
                // Формат: PID USER STARTED COMMAND
                String[] parts = line.trim().split("\\s+", 4);
                if (parts.length >= 4) {
                    info.setPid(parts[0]);
                    info.setUser(parts[1]);
                    info.setCommand(parts[3]);
                    info.setArguments(parts[3]);
                }
            } else if (os.contains("windows")) {
                // Обработка CSV формата от wmic
                String[] parts = line.split(",");
                if (parts.length >= 3) {
                    info.setPid(parts[2]);
                    info.setCommand(parts[1]);
                    info.setArguments(parts[1]);
                }
            }
            
            return info.getPid() != null ? info : null;
            
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Анализ поведения процесса
     */
    private void analyzeProcessBehavior(ProcessInfo process) {
        // Проверка аргументов командной строки на соответствие pg_dump паттернам
        int patternMatches = countPgDumpPatterns(process.getArguments());
        process.setPgDumpPatternScore(patternMatches);
        
        // Анализ сетевых подключений
        analyzeProcessNetworkConnections(process);
        
        // Анализ файловых операций
        analyzeProcessFileOperations(process);
        
        logger.debug("Analyzed process: PID=" + process.getPid() + 
                    ", Pattern Score=" + patternMatches + 
                    ", Command=" + process.getCommand());
    }
    
    /**
     * Подсчет соответствий паттернам pg_dump в аргументах
     */
    private int countPgDumpPatterns(String arguments) {
        if (arguments == null) return 0;
        
        int matches = 0;
        for (Pattern pattern : pgDumpArgumentPatterns) {
            if (pattern.matcher(arguments).find()) {
                matches++;
            }
        }
        return matches;
    }
    
    /**
     * Анализ сетевых подключений процесса
     */
    private void analyzeProcessNetworkConnections(ProcessInfo process) {
        try {
            // Получаем сетевые подключения процесса
            List<NetworkConnection> connections = getProcessNetworkConnections(process.getPid());
            
            for (NetworkConnection conn : connections) {
                // Проверяем подключения к PostgreSQL портам
                if (isPostgreSQLConnection(conn)) {
                    process.incrementPostgreSQLConnections();
                    process.addNetworkConnection(conn);
                    
                    logger.debug("Found PostgreSQL connection for PID " + process.getPid() + 
                               ": " + conn.getRemoteAddress() + ":" + conn.getRemotePort());
                }
            }
            
        } catch (Exception e) {
            logger.debug("Error analyzing network connections for PID " + process.getPid() + ": " + e.getMessage());
        }
    }
    
    /**
     * Получение сетевых подключений процесса
     */
    private List<NetworkConnection> getProcessNetworkConnections(String pid) {
        List<NetworkConnection> connections = new ArrayList<>();
        
        try {
            String os = System.getProperty("os.name").toLowerCase();
            Process proc;
            
            if (os.contains("linux")) {
                // Используем netstat или ss для получения подключений
                proc = Runtime.getRuntime().exec("netstat -anp | grep " + pid);
            } else if (os.contains("windows")) {
                proc = Runtime.getRuntime().exec("netstat -ano | findstr " + pid);
            } else {
                proc = Runtime.getRuntime().exec("netstat -an");
            }
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    NetworkConnection conn = parseNetstatLine(line, pid);
                    if (conn != null) {
                        connections.add(conn);
                    }
                }
            }
            
        } catch (Exception e) {
            logger.debug("Error getting network connections: " + e.getMessage());
        }
        
        return connections;
    }
    
    /**
     * Парсинг строки netstat
     */
    private NetworkConnection parseNetstatLine(String line, String pid) {
        try {
            // Простой парсер для netstat output
            if (line.contains("ESTABLISHED") && line.contains(pid)) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length >= 4) {
                    String localAddr = parts[3];
                    String remoteAddr = parts[4];
                    
                    NetworkConnection conn = new NetworkConnection();
                    conn.setLocalAddress(extractAddress(localAddr));
                    conn.setLocalPort(extractPort(localAddr));
                    conn.setRemoteAddress(extractAddress(remoteAddr));
                    conn.setRemotePort(extractPort(remoteAddr));
                    conn.setState("ESTABLISHED");
                    
                    return conn;
                }
            }
        } catch (Exception e) {
            // Игнорируем ошибки парсинга
        }
        
        return null;
    }
    
    private String extractAddress(String addrPort) {
        int lastColon = addrPort.lastIndexOf(':');
        return lastColon > 0 ? addrPort.substring(0, lastColon) : addrPort;
    }
    
    private int extractPort(String addrPort) {
        int lastColon = addrPort.lastIndexOf(':');
        try {
            return lastColon > 0 ? Integer.parseInt(addrPort.substring(lastColon + 1)) : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    /**
     * Проверка, является ли подключение PostgreSQL
     */
    private boolean isPostgreSQLConnection(NetworkConnection conn) {
        // Проверяем стандартные порты PostgreSQL
        if (conn.getRemotePort() == POSTGRESQL_DEFAULT_PORT || 
            conn.getRemotePort() == 5000 || // HAProxy write
            conn.getRemotePort() == 5001) { // HAProxy read
            return true;
        }
        
        // Проверяем известные хосты PostgreSQL
        return postgresqlHosts.contains(conn.getRemoteAddress());
    }
    
    /**
     * Анализ файловых операций процесса
     */
    private void analyzeProcessFileOperations(ProcessInfo process) {
        try {
            // Получаем открытые файлы процесса
            List<String> openFiles = getProcessOpenFiles(process.getPid());
            
            long totalFileSize = 0;
            int dumpFileCount = 0;
            
            for (String file : openFiles) {
                // Проверяем размер файла
                try {
                    Path path = Paths.get(file);
                    if (Files.exists(path) && Files.isRegularFile(path)) {
                        long size = Files.size(path);
                        totalFileSize += size;
                        
                        // Проверяем расширения, характерные для дампов
                        if (isDumpFile(file)) {
                            dumpFileCount++;
                            process.addOutputFile(file, size);
                        }
                    }
                } catch (Exception e) {
                    // Игнорируем ошибки доступа к файлам
                }
            }
            
            process.setTotalIOBytes(totalFileSize);
            process.setDumpFileCount(dumpFileCount);
            
        } catch (Exception e) {
            logger.debug("Error analyzing file operations for PID " + process.getPid() + ": " + e.getMessage());
        }
    }
    
    /**
     * Получение списка открытых файлов процесса
     */
    private List<String> getProcessOpenFiles(String pid) {
        List<String> files = new ArrayList<>();
        
        try {
            String os = System.getProperty("os.name").toLowerCase();
            Process proc;
            
            if (os.contains("linux")) {
                // Используем lsof для получения открытых файлов
                proc = Runtime.getRuntime().exec("lsof -p " + pid + " -Fn");
            } else {
                // Для других ОС возвращаем пустой список
                return files;
            }
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("n/") && !line.contains("/proc/") && !line.contains("/dev/")) {
                        files.add(line.substring(1)); // Убираем префикс 'n'
                    }
                }
            }
            
        } catch (Exception e) {
            logger.debug("Error getting open files: " + e.getMessage());
        }
        
        return files;
    }
    
    /**
     * Проверка, является ли файл дампом
     */
    private boolean isDumpFile(String filename) {
        String lower = filename.toLowerCase();
        return lower.endsWith(".sql") || 
               lower.endsWith(".dump") || 
               lower.endsWith(".backup") || 
               lower.endsWith(".bak") ||
               lower.contains("dump") ||
               lower.contains("backup");
    }
    
    /**
     * Обновление информации о процессе
     */
    private void updateProcessInfo(ProcessInfo existing, ProcessInfo current) {
        // Обновляем метрики активности
        existing.incrementScanCount();
        
        // Перезапускаем анализ для обновления метрик
        analyzeProcessBehavior(existing);
    }
    
    /**
     * Проверка, является ли процесс подозрительным
     */
    private boolean isSuspiciousProcess(ProcessInfo process) {
        int suspicionScore = 0;
        List<String> reasons = new ArrayList<>();
        
        // 1. Проверка паттернов аргументов pg_dump (вес: 40%)
        if (process.getPgDumpPatternScore() >= 3) {
            suspicionScore += 40;
            reasons.add("High pg_dump argument pattern match (" + process.getPgDumpPatternScore() + " patterns)");
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
        
        // Записываем причины подозрений
        process.setSuspicionReasons(reasons);
        process.setSuspicionScore(suspicionScore);
        
        // Порог подозрительности: 50%
        return suspicionScore >= 50;
    }
    
    /**
     * Обработка подозрительного процесса
     */
    private void handleSuspiciousProcess(ProcessInfo process) {
        SecurityAlert alert = new SecurityAlert();
        alert.setTimestamp(LocalDateTime.now());
        alert.setAlertType("SUSPICIOUS_PGDUMP_PROCESS");
        alert.setSeverity("HIGH");
        alert.setProcessId(process.getPid());
        alert.setCommand(process.getCommand());
        alert.setArguments(process.getArguments());
        alert.setSuspicionScore(process.getSuspicionScore());
        alert.setReasons(process.getSuspicionReasons());
        alert.setNetworkConnections(process.getNetworkConnections());
        alert.setOutputFiles(process.getOutputFiles());
        
        // Логируем алерт
        logger.alert("SECURITY ALERT: Suspicious pg_dump-like process detected", alert);
        
        // Отправляем уведомление
        sendSecurityAlert(alert);
        
        // Опционально: блокируем процесс (требует привилегий)
        if (shouldBlockProcess(process)) {
            blockSuspiciousProcess(process);
        }
    }
    
    /**
     * Отправка алерта безопасности
     */
    private void sendSecurityAlert(SecurityAlert alert) {
        // Здесь можно реализовать отправку алертов в SIEM, email, Slack и т.д.
        logger.info("Security alert sent: " + alert);
        
        // Пример отправки webhook
        // sendWebhookAlert(alert);
        
        // Пример записи в базу данных
        // saveAlertToDatabase(alert);
    }
    
    /**
     * Проверка, нужно ли блокировать процесс
     */
    private boolean shouldBlockProcess(ProcessInfo process) {
        // Блокируем только процессы с очень высоким уровнем подозрений
        return process.getSuspicionScore() >= 80;
    }
    
    /**
     * Блокировка подозрительного процесса
     */
    private void blockSuspiciousProcess(ProcessInfo process) {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            Process proc;
            
            if (os.contains("linux")) {
                proc = Runtime.getRuntime().exec("kill -STOP " + process.getPid());
            } else if (os.contains("windows")) {
                proc = Runtime.getRuntime().exec("taskkill /PID " + process.getPid() + " /F");
            } else {
                logger.warn("Process blocking not supported on this OS");
                return;
            }
            
            int exitCode = proc.waitFor();
            if (exitCode == 0) {
                logger.info("Successfully blocked suspicious process PID: " + process.getPid());
            } else {
                logger.error("Failed to block process PID: " + process.getPid());
            }
            
        } catch (Exception e) {
            logger.error("Error blocking process PID " + process.getPid() + ": " + e.getMessage(), e);
        }
    }
    
    /**
     * Анализ сетевых подключений (общий)
     */
    private void analyzeNetworkConnections() {
        // Дополнительный анализ сетевой активности на уровне системы
        try {
            checkPostgreSQLConnections();
        } catch (Exception e) {
            logger.error("Error analyzing network connections: " + e.getMessage(), e);
        }
    }
    
    /**
     * Проверка подключений к PostgreSQL
     */
    private void checkPostgreSQLConnections() {
        for (String host : postgresqlHosts) {
            if (isPortOpen(host, POSTGRESQL_DEFAULT_PORT)) {
                logger.debug("PostgreSQL service is active on " + host + ":" + POSTGRESQL_DEFAULT_PORT);
            }
        }
    }
    
    /**
     * Проверка доступности порта
     */
    private boolean isPortOpen(String host, int port) {
        try (SocketChannel socketChannel = SocketChannel.open()) {
            socketChannel.configureBlocking(false);
            socketChannel.connect(new InetSocketAddress(host, port));
            
            long startTime = System.currentTimeMillis();
            while (!socketChannel.finishConnect()) {
                if (System.currentTimeMillis() - startTime >= NETWORK_TIMEOUT) {
                    return false;
                }
                Thread.sleep(10);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Анализ I/O активности
     */
    private void analyzeIOActivity() {
        try {
            // Анализ общей I/O активности системы
            OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
            
            // Мониторим системные метрики I/O
            double systemLoad = osBean.getSystemLoadAverage();
            long totalPhysicalMemory = osBean.getTotalPhysicalMemorySize();
            long freePhysicalMemory = osBean.getFreePhysicalMemorySize();
            
            logger.debug("System metrics - Load: " + systemLoad + 
                        ", Memory usage: " + formatBytes(totalPhysicalMemory - freePhysicalMemory) + 
                        "/" + formatBytes(totalPhysicalMemory));
            
        } catch (Exception e) {
            logger.debug("Error analyzing I/O activity: " + e.getMessage());
        }
    }
    
    /**
     * Очистка завершившихся процессов
     */
    private void cleanupFinishedProcesses(List<ProcessInfo> currentProcesses) {
        Set<String> currentPids = new HashSet<>();
        for (ProcessInfo process : currentProcesses) {
            currentPids.add(process.getPid() + ":" + process.getStartTime());
        }
        
        // Удаляем процессы, которых больше нет в системе
        monitoredProcesses.entrySet().removeIf(entry -> !currentPids.contains(entry.getKey()));
    }
    
    /**
     * Форматирование размера в байтах
     */
    private String formatBytes(long bytes) {
        if (bytes >= 1024 * 1024 * 1024) {
            return String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
        } else if (bytes >= 1024 * 1024) {
            return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
        } else if (bytes >= 1024) {
            return String.format("%.2f KB", bytes / 1024.0);
        } else {
            return bytes + " B";
        }
    }
    
    /**
     * Остановка мониторинга
     */
    public void stopMonitoring() {
        logger.info("Stopping process behavior monitoring...");
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(10, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        logger.info("Process behavior monitoring stopped");
    }
    
    /**
     * Главный метод для запуска приложения
     */
    public static void main(String[] args) {
        PgDumpProcessMonitor monitor = new PgDumpProcessMonitor();
        
        // Добавляем shutdown hook для корректного завершения
        Runtime.getRuntime().addShutdownHook(new Thread(monitor::stopMonitoring));
        
        try {
            monitor.startMonitoring();
            
            // Ожидание завершения
            Thread.sleep(Long.MAX_VALUE);
            
        } catch (InterruptedException e) {
            System.out.println("Monitoring interrupted");
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

/**
 * Класс для хранения информации о процессе
 */
class ProcessInfo {
    private String pid;
    private String command;
    private String arguments; 
    private java.time.Instant startTime;
    private String user;
    private int pgDumpPatternScore = 0;
    private int postgreSQLConnections = 0;
    private long totalIOBytes = 0;
    private int dumpFileCount = 0;
    private int scanCount = 0;
    private int suspicionScore = 0;
    private List<String> suspicionReasons = new ArrayList<>();
    private List<NetworkConnection> networkConnections = new ArrayList<>();
    private Map<String, Long> outputFiles = new HashMap<>();
    
    // Getters and setters
    public String getPid() { return pid; }
    public void setPid(String pid) { this.pid = pid; }
    
    public String getCommand() { return command; }
    public void setCommand(String command) { this.command = command; }
    
    public String getArguments() { return arguments; }
    public void setArguments(String arguments) { this.arguments = arguments; }
    
    public java.time.Instant getStartTime() { return startTime; }
    public void setStartTime(java.time.Instant startTime) { this.startTime = startTime; }
    
    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }
    
    public int getPgDumpPatternScore() { return pgDumpPatternScore; }
    public void setPgDumpPatternScore(int score) { this.pgDumpPatternScore = score; }
    
    public int getPostgreSQLConnections() { return postgreSQLConnections; }
    public void incrementPostgreSQLConnections() { this.postgreSQLConnections++; }
    
    public long getTotalIOBytes() { return totalIOBytes; }
    public void setTotalIOBytes(long bytes) { this.totalIOBytes = bytes; }
    
    public int getDumpFileCount() { return dumpFileCount; }
    public void setDumpFileCount(int count) { this.dumpFileCount = count; }
    
    public void incrementScanCount() { this.scanCount++; }
    public int getScanCount() { return scanCount; }
    
    public int getSuspicionScore() { return suspicionScore; }
    public void setSuspicionScore(int score) { this.suspicionScore = score; }
    
    public List<String> getSuspicionReasons() { return suspicionReasons; }
    public void setSuspicionReasons(List<String> reasons) { this.suspicionReasons = reasons; }
    
    public List<NetworkConnection> getNetworkConnections() { return networkConnections; }
    public void addNetworkConnection(NetworkConnection conn) { this.networkConnections.add(conn); }
    
    public Map<String, Long> getOutputFiles() { return outputFiles; }
    
    public void addOutputFile(String filename, long size) { 
        this.outputFiles.put(filename, size); 
    }
}

/**
 * Класс для представления сетевого подключения
 */
class NetworkConnection {
    private String localAddress;
    private int localPort;
    private String remoteAddress;
    private int remotePort;
    private String state;
    private long bytesReceived = 0;
    private long bytesSent = 0;
    private java.time.LocalDateTime establishedTime;
    
    public NetworkConnection() {
        this.establishedTime = java.time.LocalDateTime.now();
    }
    
    // Getters and setters
    public String getLocalAddress() { return localAddress; }
    public void setLocalAddress(String localAddress) { this.localAddress = localAddress; }
    
    public int getLocalPort() { return localPort; }
    public void setLocalPort(int localPort) { this.localPort = localPort; }
    
    public String getRemoteAddress() { return remoteAddress; }
    public void setRemoteAddress(String remoteAddress) { this.remoteAddress = remoteAddress; }
    
    public int getRemotePort() { return remotePort; }
    public void setRemotePort(int remotePort) { this.remotePort = remotePort; }
    
    public String getState() { return state; }
    public void setState(String state) { this.state = state; }
    
    public long getBytesReceived() { return bytesReceived; }
    public void setBytesReceived(long bytesReceived) { this.bytesReceived = bytesReceived; }
    
    public long getBytesSent() { return bytesSent; }
    public void setBytesSent(long bytesSent) { this.bytesSent = bytesSent; }
    
    public java.time.LocalDateTime getEstablishedTime() { return establishedTime; }
    
    @Override
    public String toString() {
        return String.format("%s:%d -> %s:%d [%s]", 
            localAddress, localPort, remoteAddress, remotePort, state);
    }
}

/**
 * Класс для представления алерта безопасности
 */
class SecurityAlert {
    private java.time.LocalDateTime timestamp;
    private String alertType;
    private String severity;
    private String processId;
    private String command;
    private String arguments;
    private int suspicionScore;
    private List<String> reasons;
    private List<NetworkConnection> networkConnections;
    private Map<String, Long> outputFiles;
    private String description;
    private boolean blocked = false;
    
    // Getters and setters
    public java.time.LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(java.time.LocalDateTime timestamp) { this.timestamp = timestamp; }
    
    public String getAlertType() { return alertType; }
    public void setAlertType(String alertType) { this.alertType = alertType; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public String getProcessId() { return processId; }
    public void setProcessId(String processId) { this.processId = processId; }
    
    public String getCommand() { return command; }
    public void setCommand(String command) { this.command = command; }
    
    public String getArguments() { return arguments; }
    public void setArguments(String arguments) { this.arguments = arguments; }
    
    public int getSuspicionScore() { return suspicionScore; }
    public void setSuspicionScore(int suspicionScore) { this.suspicionScore = suspicionScore; }
    
    public List<String> getReasons() { return reasons; }
    public void setReasons(List<String> reasons) { this.reasons = reasons; }
    
    public List<NetworkConnection> getNetworkConnections() { return networkConnections; }
    public void setNetworkConnections(List<NetworkConnection> networkConnections) { 
        this.networkConnections = networkConnections; 
    }
    
    public Map<String, Long> getOutputFiles() { return outputFiles; }
    public void setOutputFiles(Map<String, Long> outputFiles) { this.outputFiles = outputFiles; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public boolean isBlocked() { return blocked; }
    public void setBlocked(boolean blocked) { this.blocked = blocked; }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SecurityAlert{")
          .append("timestamp=").append(timestamp)
          .append(", type=").append(alertType)
          .append(", severity=").append(severity)
          .append(", pid=").append(processId)
          .append(", score=").append(suspicionScore)
          .append(", blocked=").append(blocked)
          .append("}");
        return sb.toString();
    }
}

/**
 * Логгер для безопасности с различными уровнями
 */
class SecurityLogger {
    private static final DateTimeFormatter TIMESTAMP_FORMAT = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    
    private final String logFormat = "[%s] [%s] %s";
    
    public void debug(String message) {
        log("DEBUG", message);
    }
    
    public void info(String message) {
        log("INFO", message);
    }
    
    public void warn(String message) {
        log("WARN", message);
    }
    
    public void error(String message) {
        log("ERROR", message);
    }
    
    public void error(String message, Throwable throwable) {
        log("ERROR", message + " - " + throwable.getMessage());
        if (throwable != null) {
            throwable.printStackTrace();
        }
    }
    
    public void alert(String message, SecurityAlert alert) {
        StringBuilder sb = new StringBuilder();
        sb.append("🚨 SECURITY ALERT 🚨\n");
        sb.append("Message: ").append(message).append("\n");
        sb.append("Alert Details:\n");
        sb.append("  - Type: ").append(alert.getAlertType()).append("\n");
        sb.append("  - Severity: ").append(alert.getSeverity()).append("\n");
        sb.append("  - Process ID: ").append(alert.getProcessId()).append("\n");
        sb.append("  - Command: ").append(alert.getCommand()).append("\n");
        sb.append("  - Suspicion Score: ").append(alert.getSuspicionScore()).append("%\n");
        
        if (alert.getReasons() != null && !alert.getReasons().isEmpty()) {
            sb.append("  - Reasons:\n");
            for (String reason : alert.getReasons()) {
                sb.append("    * ").append(reason).append("\n");
            }
        }
        
        if (alert.getNetworkConnections() != null && !alert.getNetworkConnections().isEmpty()) {
            sb.append("  - Network Connections:\n");
            for (NetworkConnection conn : alert.getNetworkConnections()) {
                sb.append("    * ").append(conn.toString()).append("\n");
            }
        }
        
        if (alert.getOutputFiles() != null && !alert.getOutputFiles().isEmpty()) {
            sb.append("  - Output Files:\n");
            for (Map.Entry<String, Long> entry : alert.getOutputFiles().entrySet()) {
                sb.append("    * ").append(entry.getKey())
                  .append(" (").append(formatBytes(entry.getValue())).append(")\n");
            }
        }
        
        log("ALERT", sb.toString());
        
        // Также сохраняем в отдельный файл алертов
        saveAlertToFile(alert);
    }
    
    private void log(String level, String message) {
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        String logMessage = String.format(logFormat, timestamp, level, message);
        System.out.println(logMessage);
        
        // Опционально: запись в файл
        // writeToLogFile(logMessage);
    }
    
    private void saveAlertToFile(SecurityAlert alert) {
        try {
            String alertJson = convertAlertToJson(alert);
            String filename = "security_alerts_" + 
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")) + ".log";
            
            // Запись в файл (в реальном приложении лучше использовать proper logging framework)
            try (java.io.FileWriter writer = new java.io.FileWriter(filename, true)) {
                writer.write(alertJson + "\n");
            }
        } catch (Exception e) {
            error("Failed to save alert to file: " + e.getMessage());
        }
    }
    
    private String convertAlertToJson(SecurityAlert alert) {
        // Простая JSON сериализация (в production лучше использовать Jackson или Gson)
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"timestamp\":\"").append(alert.getTimestamp()).append("\",");
        json.append("\"alertType\":\"").append(alert.getAlertType()).append("\",");
        json.append("\"severity\":\"").append(alert.getSeverity()).append("\",");
        json.append("\"processId\":\"").append(alert.getProcessId()).append("\",");
        json.append("\"command\":\"").append(escapeJson(alert.getCommand())).append("\",");
        json.append("\"suspicionScore\":").append(alert.getSuspicionScore()).append(",");
        json.append("\"blocked\":").append(alert.isBlocked());
        json.append("}");
        return json.toString();
    }
    
    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
    
    private String formatBytes(long bytes) {
        if (bytes >= 1024 * 1024 * 1024) {
            return String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
        } else if (bytes >= 1024 * 1024) {
            return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
        } else if (bytes >= 1024) {
            return String.format("%.2f KB", bytes / 1024.0);
        } else {
            return bytes + " B";
        }
    }
}

/**
 * Расширенный анализатор системных вызовов для детекции pg_dump активности
 */
class SystemCallAnalyzer {
    private final SecurityLogger logger = new SecurityLogger();
    
    /**
     * Анализ системных вызовов процесса с помощью strace (Linux)
     */
    public SystemCallProfile analyzeProcessSystemCalls(String pid) {
        SystemCallProfile profile = new SystemCallProfile();
        
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (!os.contains("linux")) {
                logger.debug("System call analysis is only supported on Linux");
                return profile;
            }
            
            // Запуск strace для анализа системных вызовов
            ProcessBuilder pb = new ProcessBuilder("strace", "-p", pid, "-c", "-e", 
                "trace=network,file,process", "-S", "time", "-f");
            pb.redirectErrorStream(true);
            
            Process straceProcess = pb.start();
            
            // Ждем некоторое время для сбора данных
            Thread.sleep(3000);
            
            // Завершаем strace
            straceProcess.destroy();
            
            // Анализируем вывод strace
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(straceProcess.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    parseStraceOutput(line, profile);
                }
            }
            
        } catch (Exception e) {
            logger.debug("Error analyzing system calls for PID " + pid + ": " + e.getMessage());
        }
        
        return profile;
    }
    
    /**
     * Парсинг вывода strace
     */
    private void parseStraceOutput(String line, SystemCallProfile profile) {
        // Анализируем характерные для pg_dump системные вызовы
        if (line.contains("connect(") && line.contains("5432")) {
            profile.incrementPostgreSQLConnects();
        }
        
        if (line.contains("read(") || line.contains("recv(")) {
            profile.incrementReadCalls();
            // Извлекаем размер данных если возможно
            extractDataSize(line, profile, true);
        }
        
        if (line.contains("write(") || line.contains("send(")) {
            profile.incrementWriteCalls();
            extractDataSize(line, profile, false);
        }
        
        if (line.contains("openat(") || line.contains("open(")) {
            profile.incrementFileOpens();
        }
        
        // pg_dump специфичные паттерны
        if (line.contains("COPY") || line.contains("SELECT") || line.contains("pg_dump")) {
            profile.incrementDatabaseQueries();
        }
    }
    
    /**
     * Извлечение размера данных из системного вызова
     */
    private void extractDataSize(String line, SystemCallProfile profile, boolean isRead) {
        try {
            // Простой парсер для извлечения размера из strace вывода
            // Формат: syscall(...) = SIZE
            int equalPos = line.lastIndexOf(" = ");
            if (equalPos > 0) {
                String sizeStr = line.substring(equalPos + 3).trim();
                long size = Long.parseLong(sizeStr);
                
                if (isRead) {
                    profile.addBytesRead(size);
                } else {
                    profile.addBytesWritten(size);
                }
            }
        } catch (Exception e) {
            // Игнорируем ошибки парсинга
        }
    }
}

/**
 * Профиль системных вызовов процесса
 */
class SystemCallProfile {
    private int postgreSQLConnects = 0;
    private int readCalls = 0;
    private int writeCalls = 0;
    private int fileOpens = 0;
    private int databaseQueries = 0;
    
    private long totalBytesRead = 0;
    private long totalBytesWritten = 0;
    
    private java.time.LocalDateTime profileTime = java.time.LocalDateTime.now();
    
    // Increment methods
    public void incrementPostgreSQLConnects() { this.postgreSQLConnects++; }
    public void incrementReadCalls() { this.readCalls++; }
    public void incrementWriteCalls() { this.writeCalls++; }
    public void incrementFileOpens() { this.fileOpens++; }
    public void incrementDatabaseQueries() { this.databaseQueries++; }
    
    public void addBytesRead(long bytes) { this.totalBytesRead += bytes; }
    public void addBytesWritten(long bytes) { this.totalBytesWritten += bytes; }
    
    // Getters
    public int getPostgreSQLConnects() { return postgreSQLConnects; }
    public int getReadCalls() { return readCalls; }
    public int getWriteCalls() { return writeCalls; }
    public int getFileOpens() { return fileOpens; }
    public int getDatabaseQueries() { return databaseQueries; }
    public long getTotalBytesRead() { return totalBytesRead; }
    public long getTotalBytesWritten() { return totalBytesWritten; }
    public java.time.LocalDateTime getProfileTime() { return profileTime; }
    
    /**
     * Вычисляет оценку подозрительности на основе системных вызовов
     */
    public int calculateSuspicionScore() {
        int score = 0;
        
        // PostgreSQL подключения (высокий вес)
        if (postgreSQLConnects > 0) {
            score += Math.min(postgreSQLConnects * 25, 50);
        }
        
        // Большое количество чтения данных
        if (totalBytesRead > 10 * 1024 * 1024) { // > 10MB
            score += 20;
        }
        
        // Большое количество записи данных
        if (totalBytesWritten > 5 * 1024 * 1024) { // > 5MB
            score += 15;
        }
        
        // Много файловых операций
        if (fileOpens > 10) {
            score += 10;
        }
        
        // SQL запросы
        if (databaseQueries > 0) {
            score += Math.min(databaseQueries * 5, 15);
        }
        
        return Math.min(score, 100);
    }
    
    @Override
    public String toString() {
        return String.format("SystemCallProfile{pgConnects=%d, reads=%d, writes=%d, " +
                           "fileOpens=%d, queries=%d, bytesRead=%d, bytesWritten=%d}",
                           postgreSQLConnects, readCalls, writeCalls, fileOpens, 
                           databaseQueries, totalBytesRead, totalBytesWritten);
    }
}

/**
 * Дополнительные методы для PgDumpProcessMonitor класса
 * (эти методы должны быть добавлены в основной класс PgDumpProcessMonitor)
 */
class PgDumpProcessMonitorExtensions {
    
    /**
     * Усовершенствованный анализ поведения процесса с использованием системных вызовов
     */
    public void enhancedProcessAnalysis(ProcessInfo process, PgDumpProcessMonitor monitor) {
        SystemCallAnalyzer analyzer = new SystemCallAnalyzer();
        
        // Анализируем системные вызовы
        SystemCallProfile syscallProfile = analyzer.analyzeProcessSystemCalls(process.getPid());
        
        // Добавляем анализ системных вызовов к общей оценке подозрительности
        int syscallScore = syscallProfile.calculateSuspicionScore();
        
        // Обновляем общий score процесса
        int currentScore = process.getSuspicionScore();
        int enhancedScore = Math.min(currentScore + syscallScore, 100);
        process.setSuspicionScore(enhancedScore);
        
        // Добавляем причины, основанные на системных вызовах
        List<String> reasons = new ArrayList<>(process.getSuspicionReasons());
        
        if (syscallProfile.getPostgreSQLConnects() > 0) {
            reasons.add("Direct PostgreSQL connections detected (" + 
                       syscallProfile.getPostgreSQLConnects() + " connects)");
        }
        
        if (syscallProfile.getTotalBytesRead() > 10 * 1024 * 1024) {
            reasons.add("Large data reading activity (" + 
                       formatBytes(syscallProfile.getTotalBytesRead()) + " read)");
        }
        
        if (syscallProfile.getTotalBytesWritten() > 5 * 1024 * 1024) {
            reasons.add("Large data writing activity (" + 
                       formatBytes(syscallProfile.getTotalBytesWritten()) + " written)");
        }
        
        if (syscallProfile.getDatabaseQueries() > 0) {
            reasons.add("Database query patterns detected (" + 
                       syscallProfile.getDatabaseQueries() + " queries)");
        }
        
        process.setSuspicionReasons(reasons);
        
        SecurityLogger logger = new SecurityLogger();
        logger.debug("Enhanced analysis for PID " + process.getPid() + 
                    ": syscall_score=" + syscallScore + 
                    ", total_score=" + enhancedScore + 
                    ", profile=" + syscallProfile.toString());
    }
    
    private String formatBytes(long bytes) {
        if (bytes >= 1024 * 1024 * 1024) {
            return String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
        } else if (bytes >= 1024 * 1024) {
            return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
        } else if (bytes >= 1024) {
            return String.format("%.2f KB", bytes / 1024.0);
        } else {
            return bytes + " B";
        }
    }
}
