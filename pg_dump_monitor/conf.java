/**
 * Конфигурация для мониторинга pg_dump процессов
 */
class MonitorConfiguration {
    // Пороги подозрительности
    public static final int SUSPICION_THRESHOLD = 50;
    public static final int BLOCK_THRESHOLD = 80;
    
    // Пороги для данных
    public static final long SUSPICIOUS_DATA_THRESHOLD = 50 * 1024 * 1024; // 50MB
    public static final long LARGE_READ_THRESHOLD = 10 * 1024 * 1024; // 10MB
    public static final long LARGE_WRITE_THRESHOLD = 5 * 1024 * 1024; // 5MB
    
    // Интервалы мониторинга
    public static final long MONITORING_INTERVAL = 5000; // 5 секунд
    public static final long SYSCALL_ANALYSIS_DURATION = 3000; // 3 секунды
    public static final int NETWORK_TIMEOUT = 3000; // 3 секунды
    
    // PostgreSQL настройки
    public static final int POSTGRESQL_DEFAULT_PORT = 5432;
    public static final int HAPROXY_WRITE_PORT = 5000;
    public static final int HAPROXY_READ_PORT = 5001;
    
    // Веса для оценки подозрительности
    public static final int PATTERN_WEIGHT = 40;
    public static final int NETWORK_WEIGHT = 30;
    public static final int IO_WEIGHT = 20;
    public static final int FILES_WEIGHT = 10;
    
    // Минимальные пороги для срабатывания
    public static final int MIN_PATTERN_MATCHES = 3;
    public static final int MIN_FILE_OPERATIONS = 10;
    public static final int MIN_DATABASE_QUERIES = 1;
    
    // Настройки логирования
    public static final boolean ENABLE_DEBUG_LOGGING = true;
    public static final boolean ENABLE_ALERT_FILE_LOGGING = true;
    public static final String ALERT_LOG_DIRECTORY = "./security_logs/";
    
    // Настройки блокировки
    public static final boolean ENABLE_PROCESS_BLOCKING = false; // По умолчанию отключено
    public static final boolean REQUIRE_CONFIRMATION = true;
    
    private static MonitorConfiguration instance;
    
    private MonitorConfiguration() {}
    
    public static MonitorConfiguration getInstance() {
        if (instance == null) {
            synchronized (MonitorConfiguration.class) {
                if (instance == null) {
                    instance = new MonitorConfiguration();
                }
            }
        }
        return instance;
    }
}

/**
 * Улучшенный детектор pg_dump активности с дополнительными эвристиками
 */
class AdvancedPgDumpDetector {
    private final SecurityLogger logger = new SecurityLogger();
    private final SystemCallAnalyzer syscallAnalyzer = new SystemCallAnalyzer();
    
    /**
     * Комплексный анализ процесса на предмет pg_dump активности
     */
    public DetectionResult analyzeProcess(ProcessInfo process) {
        DetectionResult result = new DetectionResult();
        result.setProcessId(process.getPid());
        result.setAnalysisTime(java.time.LocalDateTime.now());
        
        // 1. Анализ аргументов командной строки
        CommandLineAnalysis cmdAnalysis = analyzeCommandLine(process);
        result.setCommandLineAnalysis(cmdAnalysis);
        
        // 2. Анализ сетевой активности
        NetworkAnalysis netAnalysis = analyzeNetworkActivity(process);
        result.setNetworkAnalysis(netAnalysis);
        
        // 3. Анализ файловых операций
        FileAnalysis fileAnalysis = analyzeFileActivity(process);
        result.setFileAnalysis(fileAnalysis);
        
        // 4. Анализ системных вызовов
        SystemCallProfile syscallProfile = syscallAnalyzer.analyzeProcessSystemCalls(process.getPid());
        result.setSystemCallProfile(syscallProfile);
        
        // 5. Эвристический анализ
        HeuristicAnalysis heuristicAnalysis = performHeuristicAnalysis(process, result);
        result.setHeuristicAnalysis(heuristicAnalysis);
        
        // 6. Вычисление финального скора
        int finalScore = calculateFinalSuspicionScore(result);
        result.setFinalSuspicionScore(finalScore);
        result.setIsSuspicious(finalScore >= MonitorConfiguration.SUSPICION_THRESHOLD);
        result.setRecommendBlock(finalScore >= MonitorConfiguration.BLOCK_THRESHOLD);
        
        logger.debug("Advanced detection result for PID " + process.getPid() + 
                    ": score=" + finalScore + ", suspicious=" + result.isSuspicious());
        
        return result;
    }
    
    /**
     * Анализ командной строки
     */
    private CommandLineAnalysis analyzeCommandLine(ProcessInfo process) {
        CommandLineAnalysis analysis = new CommandLineAnalysis();
        String args = process.getArguments() != null ? process.getArguments().toLowerCase() : "";
        String cmd = process.getCommand() != null ? process.getCommand().toLowerCase() : "";
        
        // Проверяем на переименованный pg_dump
        analysis.setLikelyRenamed(!cmd.contains("pg_dump") && 
                                 process.getPgDumpPatternScore() >= MonitorConfiguration.MIN_PATTERN_MATCHES);
        
        // Ищем специфичные паттерны
        analysis.setHasHostParameter(args.contains("--host") || args.contains("-h"));
        analysis.setHasPortParameter(args.contains("--port") || args.contains("-p"));
        analysis.setHasUserParameter(args.contains("--username") || args.contains("-u"));
        analysis.setHasDatabaseParameter(args.contains("--dbname") || args.contains("-d"));
        analysis.setHasFormatParameter(args.contains("--format") || args.contains("-f"));
        
        // Проверяем на параметры, характерные для массового дампа
        analysis.setHasSchemaOnly(args.contains("--schema-only"));
        analysis.setHasDataOnly(args.contains("--data-only"));
        analysis.setHasAllDatabases(args.contains("--all") || args.contains("-a"));
        
        // Подозрительные паттерны вывода
        analysis.setOutputToFile(args.contains(">") || args.contains("--file"));
        analysis.setOutputToRemote(args.contains("ssh") || args.contains("scp") || args.contains("rsync"));
        
        analysis.setPatternScore(process.getPgDumpPatternScore());
        
        return analysis;
    }
    
    /**
     * Анализ сетевой активности
     */
    private NetworkAnalysis analyzeNetworkActivity(ProcessInfo process) {
        NetworkAnalysis analysis = new NetworkAnalysis();
        
        List<NetworkConnection> connections = process.getNetworkConnections();
        analysis.setTotalConnections(connections.size());
        
        int pgConnections = 0;
        int suspiciousConnections = 0;
        
        for (NetworkConnection conn : connections) {
            if (isPostgreSQLPort(conn.getRemotePort())) {
                pgConnections++;
            }
            
            // Подозрительные подключения (необычные порты, внешние хосты)
            if (isSuspiciousConnection(conn)) {
                suspiciousConnections++;
            }
        }
        
        analysis.setPostgreSQLConnections(pgConnections);
        analysis.setSuspiciousConnections(suspiciousConnections);
        analysis.setHasExternalConnections(hasExternalConnections(connections));
        
        return analysis;
    }
    
    /**
     * Анализ файловой активности
     */
    private FileAnalysis analyzeFileActivity(ProcessInfo process) {
        FileAnalysis analysis = new FileAnalysis();
        
        Map<String, Long> outputFiles = process.getOutputFiles();
        analysis.setTotalOutputFiles(outputFiles.size());
        analysis.setTotalOutputSize(process.getTotalIOBytes());
        
        int largeDumpFiles = 0;
        int suspiciousLocations = 0;
        
        for (Map.Entry<String, Long> entry : outputFiles.entrySet()) {
            String file = entry.getKey();
            Long size = entry.getValue();
            
            if (size > MonitorConfiguration.SUSPICIOUS_DATA_THRESHOLD) {
                largeDumpFiles++;
            }
            
            if (isSuspiciousFileLocation(file)) {
                suspiciousLocations++;
            }
        }
        
        analysis.setLargeDumpFiles(largeDumpFiles);
        analysis.setSuspiciousFileLocations(suspiciousLocations);
        analysis.setHasDumpFileExtensions(hasDumpFileExtensions(outputFiles.keySet()));
        
        return analysis;
    }
    
    /**
     * Проверяет, является ли порт PostgreSQL портом
     */
    private boolean isPostgreSQLPort(int port) {
        return port == MonitorConfiguration.POSTGRESQL_DEFAULT_PORT || 
               port == MonitorConfiguration.HAPROXY_WRITE_PORT || 
               port == MonitorConfiguration.HAPROXY_READ_PORT;
    }
    
    /**
     * Проверяет подозрительные сетевые подключения
     */
    private boolean isSuspiciousConnection(NetworkConnection conn) {
        // Внешние IP-адреса (упрощенная проверка)
        if (conn.getRemoteAddress() != null && 
            !conn.getRemoteAddress().startsWith("10.") && 
            !conn.getRemoteAddress().startsWith("192.168.") && 
            !conn.getRemoteAddress().equals("127.0.0.1")) {
            return true;
        }
        
        // Необычные порты для PostgreSQL
        if (isPostgreSQLPort(conn.getRemotePort()) && 
            !conn.getRemoteAddress().equals("127.0.0.1") && 
            !conn.getRemoteAddress().startsWith("10.")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Проверяет наличие внешних подключений
     */
    private boolean hasExternalConnections(List<NetworkConnection> connections) {
        return connections.stream().anyMatch(this::isSuspiciousConnection);
    }
    
    /**
     * Проверяет подозрительные расположения файлов
     */
    private boolean isSuspiciousFileLocation(String filePath) {
        String lowerPath = filePath.toLowerCase();
        return lowerPath.contains("/tmp/") || 
               lowerPath.contains("/dev/shm/") || 
               lowerPath.contains("/var/tmp/") || 
               lowerPath.matches(".*/home/[^/]+/.*\\.(sql|dump|backup)");
    }
    
    /**
     * Проверяет наличие расширений файлов дампов
     */
    private boolean hasDumpFileExtensions(Set<String> files) {
        return files.stream().anyMatch(file -> 
            file.toLowerCase().endsWith(".sql") || 
            file.toLowerCase().endsWith(".dump") || 
            file.toLowerCase().endsWith(".backup") || 
            file.toLowerCase().endsWith(".bak"));
    }
    
    /**
     * Эвристический анализ поведения процесса
     */
    private HeuristicAnalysis performHeuristicAnalysis(ProcessInfo process, DetectionResult partialResult) {
        HeuristicAnalysis analysis = new HeuristicAnalysis();
        
        // 1. Проверка на высокую скорость чтения/записи
        long ioBytesPerSecond = calculateIoRate(process, partialResult.getFileAnalysis());
        analysis.setHighIoRate(ioBytesPerSecond > 5 * 1024 * 1024); // > 5MB/s
        
        // 2. Проверка на короткое время жизни процесса (быстрый дамп)
        analysis.setShortLivedProcess(isShortLivedProcess(process));
        
        // 3. Проверка на необычное время выполнения (ночью)
        analysis.setUnusualExecutionTime(isUnusualExecutionTime());
        
        // 4. Проверка на аномальное использование CPU/памяти
        analysis.setHighResourceUsage(hasHighResourceUsage(process));
        
        return analysis;
    }
    
    /**
     * Вычисляет скорость I/O операций
     */
    private long calculateIoRate(ProcessInfo process, FileAnalysis fileAnalysis) {
        // Упрощенный расчет - предполагаем, что весь I/O произошел за время жизни процесса
        if (process.getStartTime() != null) {
            long processDuration = java.time.Duration.between(
                process.getStartTime(), java.time.Instant.now()).getSeconds();
            if (processDuration > 0) {
                return fileAnalysis.getTotalOutputSize() / processDuration;
            }
        }
        return 0;
    }
    
    /**
     * Проверяет, является ли процесс короткоживущим
     */
    private boolean isShortLivedProcess(ProcessInfo process) {
        if (process.getStartTime() != null) {
            long duration = java.time.Duration.between(
                process.getStartTime(), java.time.Instant.now()).getSeconds();
            return duration < 30; // Менее 30 секунд
        }
        return false;
    }
    
    /**
     * Проверяет необычное время выполнения (ночью)
     */
    private boolean isUnusualExecutionTime() {
        int hour = java.time.LocalTime.now().getHour();
        return hour >= 0 && hour <= 5; // С полуночи до 5 утра
    }
    
    /**
     * Проверяет высокое использование ресурсов
     */
    private boolean hasHighResourceUsage(ProcessInfo process) {
        // В реальной реализации нужно получить метрики процесса
        return false; // Заглушка
    }
    
    /**
     * Вычисляет итоговый score подозрительности
     */
    private int calculateFinalSuspicionScore(DetectionResult result) {
        int score = 0;
        
        // 1. Вес анализа командной строки
        CommandLineAnalysis cmd = result.getCommandLineAnalysis();
        if (cmd.getPatternScore() >= MonitorConfiguration.MIN_PATTERN_MATCHES) {
            score += MonitorConfiguration.PATTERN_WEIGHT;
        }
        
        // 2. Вес сетевой активности
        NetworkAnalysis net = result.getNetworkAnalysis();
        if (net.getPostgreSQLConnections() > 0) {
            score += MonitorConfiguration.NETWORK_WEIGHT;
        }
        
        // 3. Вес файловых операций
        FileAnalysis file = result.getFileAnalysis();
        if (file.getTotalOutputSize() > MonitorConfiguration.SUSPICIOUS_DATA_THRESHOLD) {
            score += MonitorConfiguration.IO_WEIGHT;
        }
        
        // 4. Вес системных вызовов
        SystemCallProfile syscall = result.getSystemCallProfile();
        if (syscall.getPostgreSQLConnects() > 0 || 
            syscall.getTotalBytesRead() > MonitorConfiguration.LARGE_READ_THRESHOLD) {
            score += 20; // Дополнительный вес для системных вызовов
        }
        
        // 5. Эвристические правила
        HeuristicAnalysis heuristic = result.getHeuristicAnalysis();
        if (heuristic.isHighIoRate() || heuristic.isShortLivedProcess()) {
            score += 10;
        }
        
        return Math.min(score, 100);
    }
}

/**
 * Результат детектирования pg_dump активности
 */
class DetectionResult {
    private String processId;
    private java.time.LocalDateTime analysisTime;
    private CommandLineAnalysis commandLineAnalysis;
    private NetworkAnalysis networkAnalysis;
    private FileAnalysis fileAnalysis;
    private SystemCallProfile systemCallProfile;
    private HeuristicAnalysis heuristicAnalysis;
    private int finalSuspicionScore;
    private boolean isSuspicious;
    private boolean recommendBlock;
    
    // Getters and setters
    public String getProcessId() { return processId; }
    public void setProcessId(String processId) { this.processId = processId; }
    
    public java.time.LocalDateTime getAnalysisTime() { return analysisTime; }
    public void setAnalysisTime(java.time.LocalDateTime analysisTime) { this.analysisTime = analysisTime; }
    
    public CommandLineAnalysis getCommandLineAnalysis() { return commandLineAnalysis; }
    public void setCommandLineAnalysis(CommandLineAnalysis commandLineAnalysis) { this.commandLineAnalysis = commandLineAnalysis; }
    
    public NetworkAnalysis getNetworkAnalysis() { return networkAnalysis; }
    public void setNetworkAnalysis(NetworkAnalysis networkAnalysis) { this.networkAnalysis = networkAnalysis; }
    
    public FileAnalysis getFileAnalysis() { return fileAnalysis; }
    public void setFileAnalysis(FileAnalysis fileAnalysis) { this.fileAnalysis = fileAnalysis; }
    
    public SystemCallProfile getSystemCallProfile() { return systemCallProfile; }
    public void setSystemCallProfile(SystemCallProfile systemCallProfile) { this.systemCallProfile = systemCallProfile; }
    
    public HeuristicAnalysis getHeuristicAnalysis() { return heuristicAnalysis; }
    public void setHeuristicAnalysis(HeuristicAnalysis heuristicAnalysis) { this.heuristicAnalysis = heuristicAnalysis; }
    
    public int getFinalSuspicionScore() { return finalSuspicionScore; }
    public void setFinalSuspicionScore(int finalSuspicionScore) { this.finalSuspicionScore = finalSuspicionScore; }
    
    public boolean isSuspicious() { return isSuspicious; }
    public void setIsSuspicious(boolean isSuspicious) { this.isSuspicious = isSuspicious; }
    
    public boolean isRecommendBlock() { return recommendBlock; }
    public void setRecommendBlock(boolean recommendBlock) { this.recommendBlock = recommendBlock; }
}

/**
 * Анализ командной строки процесса
 */
class CommandLineAnalysis {
    private boolean likelyRenamed;
    private boolean hasHostParameter;
    private boolean hasPortParameter;
    private boolean hasUserParameter;
    private boolean hasDatabaseParameter;
    private boolean hasFormatParameter;
    private boolean hasSchemaOnly;
    private boolean hasDataOnly;
    private boolean hasAllDatabases;
    private boolean outputToFile;
    private boolean outputToRemote;
    private int patternScore;
    
    // Getters and setters
    public boolean isLikelyRenamed() { return likelyRenamed; }
    public void setLikelyRenamed(boolean likelyRenamed) { this.likelyRenamed = likelyRenamed; }
    
    public boolean isHasHostParameter() { return hasHostParameter; }
    public void setHasHostParameter(boolean hasHostParameter) { this.hasHostParameter = hasHostParameter; }
    
    public boolean isHasPortParameter() { return hasPortParameter; }
    public void setHasPortParameter(boolean hasPortParameter) { this.hasPortParameter = hasPortParameter; }
    
    public boolean isHasUserParameter() { return hasUserParameter; }
    public void setHasUserParameter(boolean hasUserParameter) { this.hasUserParameter = hasUserParameter; }
    
    public boolean isHasDatabaseParameter() { return hasDatabaseParameter; }
    public void setHasDatabaseParameter(boolean hasDatabaseParameter) { this.hasDatabaseParameter = hasDatabaseParameter; }
    
    public boolean isHasFormatParameter() { return hasFormatParameter; }
    public void setHasFormatParameter(boolean hasFormatParameter) { this.hasFormatParameter = hasFormatParameter; }
    
    public boolean isHasSchemaOnly() { return hasSchemaOnly; }
    public void setHasSchemaOnly(boolean hasSchemaOnly) { this.hasSchemaOnly = hasSchemaOnly; }
    
    public boolean isHasDataOnly() { return hasDataOnly; }
    public void setHasDataOnly(boolean hasDataOnly) { this.hasDataOnly = hasDataOnly; }
    
    public boolean isHasAllDatabases() { return hasAllDatabases; }
    public void setHasAllDatabases(boolean hasAllDatabases) { this.hasAllDatabases = hasAllDatabases; }
    
    public boolean isOutputToFile() { return outputToFile; }
    public void setOutputToFile(boolean outputToFile) { this.outputToFile = outputToFile; }
    
    public boolean isOutputToRemote() { return outputToRemote; }
    public void setOutputToRemote(boolean outputToRemote) { this.outputToRemote = outputToRemote; }
    
    public int getPatternScore() { return patternScore; }
    public void setPatternScore(int patternScore) { this.patternScore = patternScore; }
}

/**
 * Анализ сетевой активности процесса
 */
class NetworkAnalysis {
    private int totalConnections;
    private int postgreSQLConnections;
    private int suspiciousConnections;
    private boolean hasExternalConnections;
    
    // Getters and setters
    public int getTotalConnections() { return totalConnections; }
    public void setTotalConnections(int totalConnections) { this.totalConnections = totalConnections; }
    
    public int getPostgreSQLConnections() { return postgreSQLConnections; }
    public void setPostgreSQLConnections(int postgreSQLConnections) { this.postgreSQLConnections = postgreSQLConnections; }
    
    public int getSuspiciousConnections() { return suspiciousConnections; }
    public void setSuspiciousConnections(int suspiciousConnections) { this.suspiciousConnections = suspiciousConnections; }
    
    public boolean isHasExternalConnections() { return hasExternalConnections; }
    public void setHasExternalConnections(boolean hasExternalConnections) { this.hasExternalConnections = hasExternalConnections; }
}

/**
 * Анализ файловой активности процесса
 */
class FileAnalysis {
    private int totalOutputFiles;
    private long totalOutputSize;
    private int largeDumpFiles;
    private int suspiciousFileLocations;
    private boolean hasDumpFileExtensions;
    
    // Getters and setters
    public int getTotalOutputFiles() { return totalOutputFiles; }
    public void setTotalOutputFiles(int totalOutputFiles) { this.totalOutputFiles = totalOutputFiles; }
    
    public long getTotalOutputSize() { return totalOutputSize; }
    public void setTotalOutputSize(long totalOutputSize) { this.totalOutputSize = totalOutputSize; }
    
    public int getLargeDumpFiles() { return largeDumpFiles; }
    public void setLargeDumpFiles(int largeDumpFiles) { this.largeDumpFiles = largeDumpFiles; }
    
    public int getSuspiciousFileLocations() { return suspiciousFileLocations; }
    public void setSuspiciousFileLocations(int suspiciousFileLocations) { this.suspiciousFileLocations = suspiciousFileLocations; }
    
    public boolean isHasDumpFileExtensions() { return hasDumpFileExtensions; }
    public void setHasDumpFileExtensions(boolean hasDumpFileExtensions) { this.hasDumpFileExtensions = hasDumpFileExtensions; }
}

/**
 * Эвристический анализ поведения процесса
 */
class HeuristicAnalysis {
    private boolean highIoRate;
    private boolean shortLivedProcess;
    private boolean unusualExecutionTime;
    private boolean highResourceUsage;
    
    // Getters and setters
    public boolean isHighIoRate() { return highIoRate; }
    public void setHighIoRate(boolean highIoRate) { this.highIoRate = highIoRate; }
    
    public boolean isShortLivedProcess() { return shortLivedProcess; }
    public void setShortLivedProcess(boolean shortLivedProcess) { this.shortLivedProcess = shortLivedProcess; }
    
    public boolean isUnusualExecutionTime() { return unusualExecutionTime; }
    public void setUnusualExecutionTime(boolean unusualExecutionTime) { this.unusualExecutionTime = unusualExecutionTime; }
    
    public boolean isHighResourceUsage() { return highResourceUsage; }
    public void setHighResourceUsage(boolean highResourceUsage) { this.highResourceUsage = highResourceUsage; }
}
