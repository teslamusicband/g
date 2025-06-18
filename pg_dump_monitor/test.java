package com.security.pgdump.monitor;

import org.junit.jupiter.api.*;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PgDumpProcessMonitorTest {
    
    private PgDumpProcessMonitor monitor;
    private SecurityLogger mockLogger;
    
    @BeforeEach
    void setUp() {
        mockLogger = mock(SecurityLogger.class);
        monitor = new PgDumpProcessMonitor() {
            @Override
            protected SecurityLogger createLogger() {
                return mockLogger;
            }
        };
    }
    
    @AfterEach
    void tearDown() {
        monitor.stopMonitoring();
    }

    // Тест базовой функциональности мониторинга
    @Test
    void testStartAndStopMonitoring() {
        monitor.startMonitoring();
        verify(mockLogger).info("Starting PostgreSQL pg_dump behavior monitoring...");
        verify(mockLogger).info("Process behavior monitoring started successfully");
        
        monitor.stopMonitoring();
        verify(mockLogger).info("Stopping process behavior monitoring...");
        verify(mockLogger).info("Process behavior monitoring stopped");
    }

    // Тест обнаружения подозрительного процесса
    @Test
    void testDetectSuspiciousProcess() {
        // Подготовка тестовых данных
        ProcessInfo suspiciousProcess = createSuspiciousProcess();
        List<ProcessInfo> processes = Collections.singletonList(suspiciousProcess);
        
        // Мокируем вызовы системы
        try (MockedStatic<ProcessHandle> mocked = mockStatic(ProcessHandle.class)) {
            ProcessHandle mockHandle = mock(ProcessHandle.class);
            ProcessHandle.Info mockInfo = mock(ProcessHandle.Info.class);
            
            when(mockHandle.info()).thenReturn(mockInfo);
            when(mockInfo.command()).thenReturn(Optional.of("pg_dump"));
            when(mockInfo.arguments()).thenReturn(Optional.of(new String[]{"--host=10.0.1.10", "--dbname=prod_db"}));
            when(mockInfo.startInstant()).thenReturn(Optional.of(Instant.now()));
            when(mockInfo.user()).thenReturn(Optional.of("postgres"));
            
            when(ProcessHandle.allProcesses()).thenReturn(Stream.of(mockHandle));
            
            // Запускаем мониторинг
            monitor.startMonitoring();
            
            // Даем время для выполнения сканирования
            Thread.sleep(1000);
            
            // Проверяем, что был вызван alert
            verify(mockLogger).alert(contains("Suspicious pg_dump-like process detected"), any(SecurityAlert.class));
        } catch (InterruptedException e) {
            fail("Test interrupted");
        }
    }

    // Тест анализа командной строки
    @Test
    void testCommandLineAnalysis() {
        ProcessInfo process = new ProcessInfo();
        process.setCommand("/usr/bin/pg_dump");
        process.setArguments("--host=10.0.1.10 --port=5432 --username=admin --dbname=production -F custom --file=/tmp/dump.dump");
        
        monitor.analyzeProcessBehavior(process);
        
        assertTrue(process.getPgDumpPatternScore() >= 5, "Should detect multiple pg_dump patterns");
        assertTrue(process.getSuspicionScore() > 0, "Should have suspicion score");
    }

    // Тест анализа сетевых подключений
    @Test
    void testNetworkConnectionAnalysis() throws Exception {
        ProcessInfo process = new ProcessInfo();
        process.setPid("12345");
        
        // Мокируем вызов netstat
        Process mockProcess = mock(Process.class);
        when(mockProcess.getInputStream()).thenReturn(
            new ByteArrayInputStream("tcp 0 0 127.0.0.1:54321 10.0.1.10:5432 ESTABLISHED 12345\n".getBytes())
        );
        
        try (MockedStatic<Runtime> mockedRuntime = mockStatic(Runtime.class)) {
            Runtime mockRuntime = mock(Runtime.class);
            when(mockRuntime.exec(anyString())).thenReturn(mockProcess);
            mockedRuntime.when(Runtime::getRuntime).thenReturn(mockRuntime);
            
            monitor.analyzeProcessNetworkConnections(process);
            
            assertEquals(1, process.getPostgreSQLConnections(), "Should detect PostgreSQL connection");
            assertFalse(process.getNetworkConnections().isEmpty(), "Should have network connections");
        }
    }

    // Тест анализа файловых операций
    @Test
    void testFileOperationsAnalysis() throws Exception {
        ProcessInfo process = new ProcessInfo();
        process.setPid("12345");
        
        // Мокируем вызов lsof
        Process mockProcess = mock(Process.class);
        when(mockProcess.getInputStream()).thenReturn(
            new ByteArrayInputStream("n/tmp/dump.sql\nn/var/lib/postgresql/data\n".getBytes())
        );
        
        // Мокируем Files.size
        try (MockedStatic<Runtime> mockedRuntime = mockStatic(Runtime.class);
             MockedStatic<Files> mockedFiles = mockStatic(Files.class);
             MockedStatic<Paths> mockedPaths = mockStatic(Paths.class)) {
            
            Runtime mockRuntime = mock(Runtime.class);
            when(mockRuntime.exec(anyString())).thenReturn(mockProcess);
            mockedRuntime.when(Runtime::getRuntime).thenReturn(mockRuntime);
            
            Path mockPath = mock(Path.class);
            when(Paths.get(anyString())).thenReturn(mockPath);
            when(Files.exists(mockPath)).thenReturn(true);
            when(Files.isRegularFile(mockPath)).thenReturn(true);
            when(Files.size(mockPath)).thenReturn(100 * 1024 * 1024L); // 100MB
            
            monitor.analyzeProcessFileOperations(process);
            
            assertEquals(1, process.getDumpFileCount(), "Should detect dump file");
            assertTrue(process.getTotalIOBytes() > 0, "Should calculate total IO size");
        }
    }

    // Тест блокировки процесса
    @Test
    void testProcessBlocking() throws Exception {
        ProcessInfo process = createSuspiciousProcess();
        process.setSuspicionScore(85); // Выше порога блокировки
        
        // Мокируем Runtime.exec
        Process mockProcess = mock(Process.class);
        when(mockProcess.waitFor()).thenReturn(0);
        
        try (MockedStatic<Runtime> mockedRuntime = mockStatic(Runtime.class)) {
            Runtime mockRuntime = mock(Runtime.class);
            when(mockRuntime.exec(anyString())).thenReturn(mockProcess);
            mockedRuntime.when(Runtime::getRuntime).thenReturn(mockRuntime);
            
            monitor.blockSuspiciousProcess(process);
            
            verify(mockLogger).info("Successfully blocked suspicious process PID: " + process.getPid());
        }
    }

    // Тест анализа системных вызовов
    @Test
    void testSystemCallAnalysis() {
        SystemCallAnalyzer analyzer = new SystemCallAnalyzer();
        SystemCallProfile profile = new SystemCallProfile();
        
        analyzer.parseStraceOutput("connect(3, {sa_family=AF_INET, sin_port=htons(5432), ...", profile);
        analyzer.parseStraceOutput("read(3, \"COPY public.users (id, name) FROM stdin;\", 4096) = 36", profile);
        analyzer.parseStraceOutput("write(4, \"some data\", 1024) = 1024", profile);
        
        assertEquals(1, profile.getPostgreSQLConnects(), "Should detect PostgreSQL connect");
        assertEquals(1, profile.getReadCalls(), "Should detect read call");
        assertEquals(1, profile.getWriteCalls(), "Should detect write call");
        assertTrue(profile.calculateSuspicionScore() > 0, "Should have suspicion score");
    }

    // Тест интеграции всех компонентов
    @Test
    void testIntegratedDetection() {
        AdvancedPgDumpDetector detector = new AdvancedPgDumpDetector();
        ProcessInfo process = createSuspiciousProcess();
        
        DetectionResult result = detector.analyzeProcess(process);
        
        assertTrue(result.isSuspicious(), "Should detect as suspicious");
        assertTrue(result.getFinalSuspicionScore() >= MonitorConfiguration.SUSPICION_THRESHOLD, 
                  "Score should be above threshold");
        
        // Проверяем анализ командной строки
        CommandLineAnalysis cmdAnalysis = result.getCommandLineAnalysis();
        assertTrue(cmdAnalysis.isHasHostParameter());
        assertTrue(cmdAnalysis.isHasDatabaseParameter());
        
        // Проверяем анализ сети
        NetworkAnalysis netAnalysis = result.getNetworkAnalysis();
        assertTrue(netAnalysis.getPostgreSQLConnections() > 0);
        
        // Проверяем анализ файлов
        FileAnalysis fileAnalysis = result.getFileAnalysis();
        assertTrue(fileAnalysis.getTotalOutputSize() > 0);
    }

    // Вспомогательный метод для создания подозрительного процесса
    private ProcessInfo createSuspiciousProcess() {
        ProcessInfo process = new ProcessInfo();
        process.setPid("12345");
        process.setCommand("/usr/bin/pg_dump");
        process.setArguments("--host=10.0.1.10 --port=5432 --username=admin --dbname=production -F custom --file=/tmp/dump.dump");
        process.setStartTime(Instant.now());
        process.setUser("postgres");
        
        // Добавляем сетевое подключение
        NetworkConnection conn = new NetworkConnection();
        conn.setRemoteAddress("10.0.1.10");
        conn.setRemotePort(5432);
        process.addNetworkConnection(conn);
        
        // Добавляем файл дампа
        process.addOutputFile("/tmp/dump.dump", 100 * 1024 * 1024); // 100MB
        
        return process;
    }
}

// Дополнительные тестовые классы для проверки конфигурации и вспомогательных классов

class MonitorConfigurationTest {
    
    @Test
    void testSingletonInstance() {
        MonitorConfiguration instance1 = MonitorConfiguration.getInstance();
        MonitorConfiguration instance2 = MonitorConfiguration.getInstance();
        
        assertSame(instance1, instance2, "Should return same instance");
    }
    
    @Test
    void testConfigurationValues() {
        assertEquals(50, MonitorConfiguration.SUSPICION_THRESHOLD);
        assertEquals(80, MonitorConfiguration.BLOCK_THRESHOLD);
        assertEquals(50 * 1024 * 1024, MonitorConfiguration.SUSPICIOUS_DATA_THRESHOLD);
        assertEquals(5000, MonitorConfiguration.MONITORING_INTERVAL);
        assertTrue(MonitorConfiguration.ENABLE_DEBUG_LOGGING);
    }
}

class DetectionResultTest {
    
    @Test
    void testDetectionResultSettersAndGetters() {
        DetectionResult result = new DetectionResult();
        
        result.setProcessId("12345");
        result.setFinalSuspicionScore(75);
        result.setIsSuspicious(true);
        
        assertEquals("12345", result.getProcessId());
        assertEquals(75, result.getFinalSuspicionScore());
        assertTrue(result.isSuspicious());
        
        CommandLineAnalysis cmdAnalysis = new CommandLineAnalysis();
        cmdAnalysis.setHasHostParameter(true);
        result.setCommandLineAnalysis(cmdAnalysis);
        
        assertTrue(result.getCommandLineAnalysis().isHasHostParameter());
    }
}

class SecurityLoggerTest {
    
    @Test
    void testLoggingLevels() {
        SecurityLogger logger = new SecurityLogger();
        
        // Проверяем, что методы не бросают исключений
        assertDoesNotThrow(() -> logger.debug("Test debug"));
        assertDoesNotThrow(() -> logger.info("Test info"));
        assertDoesNotThrow(() -> logger.warn("Test warn"));
        assertDoesNotThrow(() -> logger.error("Test error"));
        
        // Проверяем alert с SecurityAlert
        SecurityAlert alert = new SecurityAlert();
        alert.setProcessId("12345");
        assertDoesNotThrow(() -> logger.alert("Test alert", alert));
    }
}

class ProcessInfoTest {
    
    @Test
    void testProcessInfoMethods() {
        ProcessInfo process = new ProcessInfo();
        
        process.setPid("12345");
        process.setCommand("pg_dump");
        process.setPgDumpPatternScore(5);
        
        assertEquals("12345", process.getPid());
        assertEquals("pg_dump", process.getCommand());
        assertEquals(5, process.getPgDumpPatternScore());
        
        // Проверяем инкрементальные методы
        process.incrementPostgreSQLConnections();
        process.incrementScanCount();
        assertEquals(1, process.getPostgreSQLConnections());
        assertEquals(1, process.getScanCount());
        
        // Проверяем добавление сетевых подключений и файлов
        NetworkConnection conn = new NetworkConnection();
        process.addNetworkConnection(conn);
        process.addOutputFile("test.dump", 1024);
        
        assertEquals(1, process.getNetworkConnections().size());
        assertEquals(1, process.getOutputFiles().size());
    }
}
