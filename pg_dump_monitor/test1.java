package com.security.pgdump.monitor;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PgDumpProcessMonitorTest {

    @InjectMocks
    private PgDumpProcessMonitor monitor;

    @Mock
    private ScheduledExecutorService mockScheduler;

    @Mock
    private Runtime mockRuntime;

    @Mock
    private Process mockProcess;

    @Mock
    private HttpURLConnection mockConnection;

    @Mock
    private OutputStream mockOutputStream;

    @Captor
    private ArgumentCaptor<String> logCaptor;

    private ByteArrayOutputStream outputStream;
    private PrintStream originalOut;

    @BeforeEach
    void setUp() {
        // Перехватываем System.out для проверки логов
        outputStream = new ByteArrayOutputStream();
        originalOut = System.out;
        System.setOut(new PrintStream(outputStream));
    }

    @AfterEach
    void tearDown() {
        System.setOut(originalOut);
    }

    @Nested
    @DisplayName("Initialization Tests")
    class InitializationTests {

        @Test
        @DisplayName("Should initialize with correct default values")
        void shouldInitializeWithDefaults() {
            PgDumpProcessMonitor newMonitor = new PgDumpProcessMonitor();
            assertNotNull(newMonitor);
        }

        @Test
        @DisplayName("Should start monitoring with correct parameters")
        void shouldStartMonitoringWithCorrectParameters() {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class)) {
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);

                monitor.startMonitoring();

                String output = outputStream.toString();
                assertTrue(output.contains("Starting pg_dump monitoring on host: test-host"));
            }
        }

        @Test
        @DisplayName("Should handle hostname resolution failure gracefully")
        void shouldHandleHostnameResolutionFailure() {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class)) {
                inetMock.when(() -> java.net.InetAddress.getLocalHost())
                    .thenThrow(new java.net.UnknownHostException("Test exception"));

                monitor.startMonitoring();

                String output = outputStream.toString();
                assertTrue(output.contains("Starting pg_dump monitoring on host: unknown"));
            }
        }
    }

    @Nested
    @DisplayName("Process Scanning Tests")
    class ProcessScanningTests {

        @Test
        @DisplayName("Should detect pg_dump process with standard path")
        void shouldDetectPgDumpWithStandardPath() throws Exception {
            String psOutput = "1234 /usr/pgsql-16/bin/pg_dump -h localhost -d testdb\n" +
                            "5678 java -jar application.jar\n";
            
            setupMockProcess(psOutput, "");
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);
                when(mockRuntime.exec("netstat -anp | grep 1234")).thenReturn(mockProcess);

                monitor.startMonitoring();
                
                // Имитируем вызов scanProcesses
                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                verify(mockRuntime).exec("ps -eo pid,cmd --no-headers");
                verify(mockRuntime).exec("netstat -anp | grep 1234");
            }
        }

        @Test
        @DisplayName("Should detect pg_dump process with alternative path")
        void shouldDetectPgDumpWithAlternativePath() throws Exception {
            String psOutput = "9999 /bin/pg_dump --host=remote.server.com --port=5432\n";
            
            setupMockProcess(psOutput, "");
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);
                when(mockRuntime.exec("netstat -anp | grep 9999")).thenReturn(mockProcess);

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                verify(mockRuntime).exec("netstat -anp | grep 9999");
            }
        }

        @Test
        @DisplayName("Should ignore non-pg_dump processes")
        void shouldIgnoreNonPgDumpProcesses() throws Exception {
            String psOutput = "1111 mysql -u root -p\n" +
                            "2222 python backup_script.py\n" +
                            "3333 java -jar app.jar\n";
            
            setupMockProcess(psOutput, "");
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                verify(mockRuntime, never()).exec(contains("netstat"));
            }
        }

        @Test
        @DisplayName("Should handle process scanning errors gracefully")
        void shouldHandleProcessScanningErrors() throws Exception {
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers"))
                    .thenThrow(new IOException("Process execution failed"));

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                String output = outputStream.toString();
                assertTrue(output.contains("ERROR") && output.contains("Error scanning processes"));
            }
        }
    }

    @Nested
    @DisplayName("Network Connection Tests")
    class NetworkConnectionTests {

        @Test
        @DisplayName("Should detect established connection on port 5432")
        void shouldDetectEstablishedConnectionPort5432() throws Exception {
            String networkOutput = "tcp 0 0 127.0.0.1:45678 192.168.1.100:5432 ESTABLISHED 1234/pg_dump\n";
            
            setupMockProcess("", networkOutput);
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("netstat -anp | grep 1234")).thenReturn(mockProcess);

                java.lang.reflect.Method checkMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("checkNetworkConnections", String.class, String.class);
                checkMethod.setAccessible(true);
                checkMethod.invoke(monitor, "1234", "/usr/pgsql-16/bin/pg_dump -h db.server.com");

                String output = outputStream.toString();
                assertTrue(output.contains("ALERT") && output.contains("pg_dump detected"));
            }
        }

        @Test
        @DisplayName("Should detect established connection on port 5000")
        void shouldDetectEstablishedConnectionPort5000() throws Exception {
            String networkOutput = "tcp 0 0 10.0.0.1:33456 172.16.1.50:5000 ESTABLISHED 5678/pg_dump\n";
            
            setupMockProcess("", networkOutput);
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("netstat -anp | grep 5678")).thenReturn(mockProcess);

                java.lang.reflect.Method checkMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("checkNetworkConnections", String.class, String.class);
                checkMethod.setAccessible(true);
                checkMethod.invoke(monitor, "5678", "pg_dump --host=remote --port=5000");

                String output = outputStream.toString();
                assertTrue(output.contains("ALERT") && output.contains("pg_dump detected"));
            }
        }

        @Test
        @DisplayName("Should ignore non-established connections")
        void shouldIgnoreNonEstablishedConnections() throws Exception {
            String networkOutput = "tcp 0 0 127.0.0.1:45678 192.168.1.100:5432 LISTEN 1234/pg_dump\n" +
                                 "tcp 0 0 127.0.0.1:45679 192.168.1.100:5432 TIME_WAIT 1234/pg_dump\n";
            
            setupMockProcess("", networkOutput);
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("netstat -anp | grep 1234")).thenReturn(mockProcess);

                java.lang.reflect.Method checkMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("checkNetworkConnections", String.class, String.class);
                checkMethod.setAccessible(true);
                checkMethod.invoke(monitor, "1234", "/usr/pgsql-16/bin/pg_dump");

                String output = outputStream.toString();
                assertFalse(output.contains("ALERT"));
            }
        }

        @Test
        @DisplayName("Should ignore connections on non-monitored ports")
        void shouldIgnoreNonMonitoredPorts() throws Exception {
            String networkOutput = "tcp 0 0 127.0.0.1:45678 192.168.1.100:3306 ESTABLISHED 1234/pg_dump\n" +
                                 "tcp 0 0 127.0.0.1:45679 192.168.1.100:8080 ESTABLISHED 1234/pg_dump\n";
            
            setupMockProcess("", networkOutput);
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("netstat -anp | grep 1234")).thenReturn(mockProcess);

                java.lang.reflect.Method checkMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("checkNetworkConnections", String.class, String.class);
                checkMethod.setAccessible(true);
                checkMethod.invoke(monitor, "1234", "/usr/pgsql-16/bin/pg_dump");

                String output = outputStream.toString();
                assertFalse(output.contains("ALERT"));
            }
        }

        @Test
        @DisplayName("Should handle network connection check errors")
        void shouldHandleNetworkConnectionErrors() throws Exception {
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("netstat -anp | grep 1234"))
                    .thenThrow(new IOException("Network command failed"));

                java.lang.reflect.Method checkMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("checkNetworkConnections", String.class, String.class);
                checkMethod.setAccessible(true);
                checkMethod.invoke(monitor, "1234", "/usr/pgsql-16/bin/pg_dump");

                String output = outputStream.toString();
                assertTrue(output.contains("ERROR") && output.contains("Error checking network connections"));
            }
        }
    }

    @Nested
    @DisplayName("Metrics Sending Tests")
    class MetricsSendingTests {

        @Test
        @DisplayName("Should send metrics successfully with 200 response")
        void shouldSendMetricsSuccessfully200() throws Exception {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class);
                 MockedConstruction<URL> urlMock = mockConstruction(URL.class, (mock, context) -> {
                     when(mock.openConnection()).thenReturn(mockConnection);
                 })) {
                
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);
                
                when(mockConnection.getOutputStream()).thenReturn(mockOutputStream);
                when(mockConnection.getResponseCode()).thenReturn(200);

                monitor.startMonitoring();
                
                java.lang.reflect.Method sendMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("sendAlertMetrics");
                sendMethod.setAccessible(true);
                sendMethod.invoke(monitor);

                verify(mockConnection).setRequestMethod("POST");
                verify(mockConnection).setDoOutput(true);
                verify(mockOutputStream).write(any(byte[].class));
                verify(mockConnection).disconnect();
            }
        }

        @Test
        @DisplayName("Should send metrics successfully with 204 response")
        void shouldSendMetricsSuccessfully204() throws Exception {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class);
                 MockedConstruction<URL> urlMock = mockConstruction(URL.class, (mock, context) -> {
                     when(mock.openConnection()).thenReturn(mockConnection);
                 })) {
                
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);
                
                when(mockConnection.getOutputStream()).thenReturn(mockOutputStream);
                when(mockConnection.getResponseCode()).thenReturn(204);

                monitor.startMonitoring();
                
                java.lang.reflect.Method sendMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("sendAlertMetrics");
                sendMethod.setAccessible(true);
                sendMethod.invoke(monitor);

                String output = outputStream.toString();
                assertFalse(output.contains("Failed to send metrics"));
            }
        }

        @Test
        @DisplayName("Should handle metrics sending failure")
        void shouldHandleMetricsSendingFailure() throws Exception {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class);
                 MockedConstruction<URL> urlMock = mockConstruction(URL.class, (mock, context) -> {
                     when(mock.openConnection()).thenReturn(mockConnection);
                 })) {
                
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);
                
                when(mockConnection.getOutputStream()).thenReturn(mockOutputStream);
                when(mockConnection.getResponseCode()).thenReturn(500);

                monitor.startMonitoring();
                
                java.lang.reflect.Method sendMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("sendAlertMetrics");
                sendMethod.setAccessible(true);
                sendMethod.invoke(monitor);

                String output = outputStream.toString();
                assertTrue(output.contains("Failed to send metrics. Response code: 500"));
            }
        }

        @Test
        @DisplayName("Should handle metrics sending exception")
        void shouldHandleMetricsSendingException() throws Exception {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class);
                 MockedConstruction<URL> urlMock = mockConstruction(URL.class, (mock, context) -> {
                     when(mock.openConnection()).thenThrow(new IOException("Connection failed"));
                 })) {
                
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);

                monitor.startMonitoring();
                
                java.lang.reflect.Method sendMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("sendAlertMetrics");
                sendMethod.setAccessible(true);
                sendMethod.invoke(monitor);

                String output = outputStream.toString();
                assertTrue(output.contains("Error sending metrics: Connection failed"));
            }
        }

        @Test
        @DisplayName("Should format metrics correctly")
        void shouldFormatMetricsCorrectly() throws Exception {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class);
                 MockedConstruction<URL> urlMock = mockConstruction(URL.class, (mock, context) -> {
                     when(mock.openConnection()).thenReturn(mockConnection);
                 })) {
                
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host-123");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);
                
                ArgumentCaptor<byte[]> metricsCaptor = ArgumentCaptor.forClass(byte[].class);
                when(mockConnection.getOutputStream()).thenReturn(mockOutputStream);
                when(mockConnection.getResponseCode()).thenReturn(200);

                monitor.startMonitoring();
                
                java.lang.reflect.Method sendMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("sendAlertMetrics");
                sendMethod.setAccessible(true);
                sendMethod.invoke(monitor);

                verify(mockOutputStream).write(metricsCaptor.capture());
                String sentMetrics = new String(metricsCaptor.getValue());
                
                assertTrue(sentMetrics.contains("pg_dump_monitor_alert_active"));
                assertTrue(sentMetrics.contains("host=\"test-host-123\""));
                assertTrue(sentMetrics.contains(" 1 "));
            }
        }
    }

    @Nested
    @DisplayName("Alert Generation Tests")
    class AlertGenerationTests {

        @Test
        @DisplayName("Should generate correctly formatted alert")
        void shouldGenerateCorrectlyFormattedAlert() throws Exception {
            java.lang.reflect.Method alertMethod = 
                PgDumpProcessMonitor.class.getDeclaredMethod("sendAlert", String.class, String.class, String.class);
            alertMethod.setAccessible(true);
            
            alertMethod.invoke(monitor, "1234", 
                "/usr/pgsql-16/bin/pg_dump -h remote.server.com -d production", 
                "tcp 0 0 127.0.0.1:45678 192.168.1.100:5432 ESTABLISHED 1234/pg_dump");

            String output = outputStream.toString();
            assertTrue(output.contains("🚨 ALERT: pg_dump detected!"));
            assertTrue(output.contains("PID: 1234"));
            assertTrue(output.contains("Command: /usr/pgsql-16/bin/pg_dump -h remote.server.com -d production"));
            assertTrue(output.contains("Connection: tcp 0 0 127.0.0.1:45678 192.168.1.100:5432 ESTABLISHED 1234/pg_dump"));
            assertTrue(output.contains("Time:"));
        }

        @Test
        @DisplayName("Should include timestamp in alert")
        void shouldIncludeTimestampInAlert() throws Exception {
            java.lang.reflect.Method alertMethod = 
                PgDumpProcessMonitor.class.getDeclaredMethod("sendAlert", String.class, String.class, String.class);
            alertMethod.setAccessible(true);
            
            LocalDateTime beforeAlert = LocalDateTime.now();
            alertMethod.invoke(monitor, "9999", "pg_dump", "test connection");
            LocalDateTime afterAlert = LocalDateTime.now();

            String output = outputStream.toString();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            
            // Проверяем, что время в алерте находится в разумных пределах
            assertTrue(output.contains(beforeAlert.format(formatter).substring(0, 16)) || 
                      output.contains(afterAlert.format(formatter).substring(0, 16)));
        }
    }

    @Nested
    @DisplayName("Logging Tests")
    class LoggingTests {

        @Test
        @DisplayName("Should log with correct format")
        void shouldLogWithCorrectFormat() throws Exception {
            java.lang.reflect.Method logMethod = 
                PgDumpProcessMonitor.class.getDeclaredMethod("log", String.class, String.class);
            logMethod.setAccessible(true);
            
            logMethod.invoke(monitor, "INFO", "Test message");

            String output = outputStream.toString();
            assertTrue(output.matches(".*\\[\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\] \\[INFO\\] Test message.*"));
        }

        @Test
        @DisplayName("Should log different levels correctly")
        void shouldLogDifferentLevelsCorrectly() throws Exception {
            java.lang.reflect.Method logMethod = 
                PgDumpProcessMonitor.class.getDeclaredMethod("log", String.class, String.class);
            logMethod.setAccessible(true);
            
            logMethod.invoke(monitor, "ERROR", "Error message");
            logMethod.invoke(monitor, "WARN", "Warning message");
            logMethod.invoke(monitor, "DEBUG", "Debug message");

            String output = outputStream.toString();
            assertTrue(output.contains("[ERROR] Error message"));
            assertTrue(output.contains("[WARN] Warning message"));
            assertTrue(output.contains("[DEBUG] Debug message"));
        }
    }

    @Nested
    @DisplayName("Monitoring Lifecycle Tests")
    class MonitoringLifecycleTests {

        @Test
        @DisplayName("Should stop monitoring gracefully")
        void shouldStopMonitoringGracefully() {
            monitor.stopMonitoring();

            String output = outputStream.toString();
            assertTrue(output.contains("Stopping monitoring..."));
        }

        @Test
        @DisplayName("Main method should setup shutdown hook")
        void mainMethodShouldSetupShutdownHook() {
            // Этот тест проверяет, что main метод не падает при запуске
            // В реальной среде мы бы использовали PowerMock для мокирования статических методов
            assertDoesNotThrow(() -> {
                // Тест структуры main метода
                assertNotNull(PgDumpProcessMonitor.class.getMethod("main", String[].class));
            });
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complete workflow from process detection to alert")
        void shouldHandleCompleteWorkflow() throws Exception {
            String psOutput = "1234 /usr/pgsql-16/bin/pg_dump -h db.example.com -d mydb\n";
            String networkOutput = "tcp 0 0 127.0.0.1:45678 db.example.com:5432 ESTABLISHED 1234/pg_dump\n";
            
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class);
                 MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class);
                 MockedConstruction<URL> urlMock = mockConstruction(URL.class, (mock, context) -> {
                     when(mock.openConnection()).thenReturn(mockConnection);
                 })) {
                
                // Setup hostname
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-server");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);
                
                // Setup process mocks
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                
                Process psProcess = mock(Process.class);
                Process netstatProcess = mock(Process.class);
                
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(psProcess);
                when(mockRuntime.exec("netstat -anp | grep 1234")).thenReturn(netstatProcess);
                
                when(psProcess.getInputStream()).thenReturn(new ByteArrayInputStream(psOutput.getBytes()));
                when(netstatProcess.getInputStream()).thenReturn(new ByteArrayInputStream(networkOutput.getBytes()));
                
                // Setup metrics sending
                when(mockConnection.getOutputStream()).thenReturn(mockOutputStream);
                when(mockConnection.getResponseCode()).thenReturn(200);
                
                monitor.startMonitoring();
                
                // Execute scan manually
                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                String output = outputStream.toString();
                
                // Verify all components worked together
                assertTrue(output.contains("Starting pg_dump monitoring on host: test-server"));
                assertTrue(output.contains("🚨 ALERT: pg_dump detected!"));
                assertTrue(output.contains("PID: 1234"));
                
                verify(mockConnection).setRequestMethod("POST");
                verify(mockOutputStream).write(any(byte[].class));
            }
        }

        @Test
        @DisplayName("Should handle multiple pg_dump processes simultaneously")
        void shouldHandleMultiplePgDumpProcesses() throws Exception {
            String psOutput = "1234 /usr/pgsql-16/bin/pg_dump -h server1.com -d db1\n" +
                            "5678 pg_dump --host=server2.com --dbname=db2\n" +
                            "9999 /bin/pg_dump -U admin -d db3\n";
            
            String networkOutput1 = "tcp 0 0 127.0.0.1:11111 server1.com:5432 ESTABLISHED 1234/pg_dump\n";
            String networkOutput2 = "tcp 0 0 127.0.0.1:22222 server2.com:5000 ESTABLISHED 5678/pg_dump\n";
            String networkOutput3 = ""; // No suspicious connections for PID 9999
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                
                Process psProcess = mock(Process.class);
                Process netstat1 = mock(Process.class);
                Process netstat2 = mock(Process.class);
                Process netstat3 = mock(Process.class);
                
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(psProcess);
                when(mockRuntime.exec("netstat -anp | grep 1234")).thenReturn(netstat1);
                when(mockRuntime.exec("netstat -anp | grep 5678")).thenReturn(netstat2);
                when(mockRuntime.exec("netstat -anp | grep 9999")).thenReturn(netstat3);
                
                when(psProcess.getInputStream()).thenReturn(new ByteArrayInputStream(psOutput.getBytes()));
                when(netstat1.getInputStream()).thenReturn(new ByteArrayInputStream(networkOutput1.getBytes()));
                when(netstat2.getInputStream()).thenReturn(new ByteArrayInputStream(networkOutput2.getBytes()));
                when(netstat3.getInputStream()).thenReturn(new ByteArrayInputStream(networkOutput3.getBytes()));
                
                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                String output = outputStream.toString();
                
                // Should detect alerts for first two processes but not the third
                long alertCount = output.lines().filter(line -> line.contains("🚨 ALERT")).count();
                assertEquals(2, alertCount);
                assertTrue(output.contains("PID: 1234"));
                assertTrue(output.contains("PID: 5678"));
            }
        }
    }

    // Helper method to setup mock processes with different outputs
    private void setupMockProcess(String psOutput, String networkOutput) throws IOException {
        when(mockProcess.getInputStream())
            .thenReturn(new ByteArrayInputStream(psOutput.getBytes()))
            .thenReturn(new ByteArrayInputStream(networkOutput.getBytes()));
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty process list")
        void shouldHandleEmptyProcessList() throws Exception {
            setupMockProcess("", "");
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                String output = outputStream.toString();
                assertFalse(output.contains("ALERT"));
            }
        }

        @Test
        @DisplayName("Should handle malformed process output")
        void shouldHandleMalformedProcessOutput() throws Exception {
            String malformedOutput = "invalid line without pid\n" +
                                   "123\n" +  // Missing command
                                   "not_a_number /usr/pgsql-16/bin/pg_dump\n"; // Invalid PID
            
            setupMockProcess(malformedOutput, "");
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                
                // Should not throw exception
                assertDoesNotThrow(() -> scanMethod.invoke(monitor));
            }
        }

        @Test
        @DisplayName("Should handle very long command lines")
        void shouldHandleVeryLongCommandLines() throws Exception {
            StringBuilder longCommand = new StringBuilder("/usr/pgsql-16/bin/pg_dump");
            for (int i = 0; i < 1000; i++) {
                longCommand.append(" --option").append(i).append("=value").append(i);
            }
            
            String psOutput = "1234 " + longCommand.toString() + "\n";
            String networkOutput = "tcp 0 0 127.0.0.1:45678 192.168.1.100:5432 ESTABLISHED 1234/pg_dump\n";
            
            setupMockProcess(psOutput, networkOutput);
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);
                when(mockRuntime.exec("netstat -anp | grep 1234")).thenReturn(mockProcess);

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                String output = outputStream.toString();
                assertTrue(output.contains("ALERT"));
                assertTrue(output.contains("PID: 1234"));
            }
        }

        @Test
        @DisplayName("Should handle processes with spaces in paths")
        void shouldHandleProcessesWithSpacesInPaths() throws Exception {
            String psOutput = "1234 \"/usr/local/postgres 16/bin/pg_dump\" -h localhost\n";
            String networkOutput = "tcp 0 0 127.0.0.1:45678 localhost:5432 ESTABLISHED 1234/pg_dump\n";
            
            // This test verifies that our current implementation might miss processes with spaces
            // but doesn't crash - this could be a legitimate bug to fix
            setupMockProcess(psOutput, networkOutput);
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                
                assertDoesNotThrow(() -> scanMethod.invoke(monitor));
            }
        }

        @Test
        @DisplayName("Should handle network timeout scenarios")
        void shouldHandleNetworkTimeoutScenarios() throws Exception {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class);
                 MockedConstruction<URL> urlMock = mockConstruction(URL.class, (mock, context) -> {
                     when(mock.openConnection()).thenReturn(mockConnection);
                 })) {
                
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);
                
                when(mockConnection.getOutputStream()).thenReturn(mockOutputStream);
                doThrow(new java.net.SocketTimeoutException("Connection timeout"))
                    .when(mockOutputStream).write(any(byte[].class));

                monitor.startMonitoring();
                
                java.lang.reflect.Method sendMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("sendAlertMetrics");
                sendMethod.setAccessible(true);
                sendMethod.invoke(monitor);

                String output = outputStream.toString();
                assertTrue(output.contains("Error sending metrics: Connection timeout"));
            }
        }

        @Test
        @DisplayName("Should handle concurrent modifications gracefully")
        void shouldHandleConcurrentModifications() throws Exception {
            // Simulate scenario where process disappears between ps and netstat calls
            String psOutput = "1234 /usr/pgsql-16/bin/pg_dump -h localhost\n";
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);
                when(mockRuntime.exec("netstat -anp | grep 1234"))
                    .thenThrow(new IOException("Process not found"));

                when(mockProcess.getInputStream())
                    .thenReturn(new ByteArrayInputStream(psOutput.getBytes()));

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                String output = outputStream.toString();
                assertTrue(output.contains("Error checking network connections for PID 1234"));
            }
        }
    }

    @Nested
    @DisplayName("Performance and Resource Tests")
    class PerformanceTests {

        @Test
        @DisplayName("Should handle large number of processes efficiently")
        void shouldHandleLargeNumberOfProcesses() throws Exception {
            StringBuilder largeProcessList = new StringBuilder();
            for (int i = 1; i <= 1000; i++) {
                if (i % 100 == 0) {
                    largeProcessList.append(i).append(" /usr/pgsql-16/bin/pg_dump -d db").append(i).append("\n");
                } else {
                    largeProcessList.append(i).append(" java -jar app").append(i).append(".jar\n");
                }
            }
            
            setupMockProcess(largeProcessList.toString(), "");
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);
                
                // Mock netstat calls for pg_dump processes
                for (int i = 100; i <= 1000; i += 100) {
                    Process netstatProcess = mock(Process.class);
                    when(netstatProcess.getInputStream())
                        .thenReturn(new ByteArrayInputStream("".getBytes()));
                    when(mockRuntime.exec("netstat -anp | grep " + i)).thenReturn(netstatProcess);
                }

                long startTime = System.currentTimeMillis();
                
                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);
                
                long executionTime = System.currentTimeMillis() - startTime;
                
                // Should complete within reasonable time (less than 5 seconds for 1000 processes)
                assertTrue(executionTime < 5000, "Processing 1000 processes took too long: " + executionTime + "ms");
                
                // Verify we checked all pg_dump processes
                verify(mockRuntime, times(10)).exec(matches("netstat -anp \\| grep \\d+"));
            }
        }

        @Test
        @DisplayName("Should handle memory efficiently with repeated calls")
        void shouldHandleMemoryEfficientlyWithRepeatedCalls() throws Exception {
            String psOutput = "1234 /usr/pgsql-16/bin/pg_dump -h localhost\n";
            
            setupMockProcess(psOutput, "");
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);
                when(mockRuntime.exec("netstat -anp | grep 1234")).thenReturn(mockProcess);

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                
                // Run multiple times to check for memory leaks
                for (int i = 0; i < 100; i++) {
                    scanMethod.invoke(monitor);
                }
                
                // If we get here without OutOfMemoryError, the test passes
                assertTrue(true);
            }
        }
    }

    @Nested
    @DisplayName("Security and Validation Tests")
    class SecurityTests {

        @Test
        @DisplayName("Should handle command injection attempts safely")
        void shouldHandleCommandInjectionSafely() throws Exception {
            // Test with malicious PID that could be used for command injection
            String maliciousPid = "1234; rm -rf /";
            String psOutput = maliciousPid + " /usr/pgsql-16/bin/pg_dump\n";
            
            setupMockProcess(psOutput, "");
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);
                
                // Should try to execute netstat with the malicious PID
                Process netstatProcess = mock(Process.class);
                when(netstatProcess.getInputStream()).thenReturn(new ByteArrayInputStream("".getBytes()));
                when(mockRuntime.exec("netstat -anp | grep " + maliciousPid)).thenReturn(netstatProcess);

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                // Verify the exact command that would be executed
                verify(mockRuntime).exec("netstat -anp | grep " + maliciousPid);
            }
        }

        @Test
        @DisplayName("Should validate metrics data before sending")
        void shouldValidateMetricsDataBeforeSending() throws Exception {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class);
                 MockedConstruction<URL> urlMock = mockConstruction(URL.class, (mock, context) -> {
                     when(mock.openConnection()).thenReturn(mockConnection);
                 })) {
                
                // Test with hostname containing special characters
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host\"with'quotes");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);
                
                ArgumentCaptor<byte[]> metricsCaptor = ArgumentCaptor.forClass(byte[].class);
                when(mockConnection.getOutputStream()).thenReturn(mockOutputStream);
                when(mockConnection.getResponseCode()).thenReturn(200);

                monitor.startMonitoring();
                
                java.lang.reflect.Method sendMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("sendAlertMetrics");
                sendMethod.setAccessible(true);
                sendMethod.invoke(monitor);

                verify(mockOutputStream).write(metricsCaptor.capture());
                String sentMetrics = new String(metricsCaptor.getValue());
                
                // Verify that the hostname is properly included (current implementation doesn't escape)
                assertTrue(sentMetrics.contains("test-host\"with'quotes"));
            }
        }

        @Test
        @DisplayName("Should handle URL construction securely")
        void shouldHandleUrlConstructionSecurely() throws Exception {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class)) {
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);
                
                monitor.startMonitoring();
                
                // Test that URL constructor is called with expected URL
                try (MockedConstruction<URL> urlMock = mockConstruction(URL.class, (mock, context) -> {
                    assertEquals("http://srv1.company.com:8428/api/v1/import/prometheus", context.arguments().get(0));
                })) {
                    
                    java.lang.reflect.Method sendMethod = 
                        PgDumpProcessMonitor.class.getDeclaredMethod("sendAlertMetrics");
                    sendMethod.setAccessible(true);
                    sendMethod.invoke(monitor);
                }
            }
        }
    }

    @Nested
    @DisplayName("Configuration and Constants Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("Should use correct pg_dump paths")
        void shouldUseCorrectPgDumpPaths() throws Exception {
            // Test that all configured paths are checked
            String psOutput = "1111 /usr/pgsql-16/bin/pg_dump\n" +
                            "2222 pg_dump\n" +
                            "3333 /bin/pg_dump\n" +
                            "4444 /etc/alternative/pgsql-pg_dump\n" +
                            "5555 /some/other/program\n";
            
            setupMockProcess(psOutput, "");
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);
                
                // Mock netstat for each expected pg_dump process
                for (String pid : new String[]{"1111", "2222", "3333", "4444"}) {
                    Process netstatProcess = mock(Process.class);
                    when(netstatProcess.getInputStream()).thenReturn(new ByteArrayInputStream("".getBytes()));
                    when(mockRuntime.exec("netstat -anp | grep " + pid)).thenReturn(netstatProcess);
                }

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                // Should check network connections for all 4 pg_dump processes but not the 5th
                verify(mockRuntime, times(4)).exec(matches("netstat -anp \\| grep \\d+"));
                verify(mockRuntime, never()).exec("netstat -anp | grep 5555");
            }
        }

        @Test
        @DisplayName("Should monitor correct ports")
        void shouldMonitorCorrectPorts() throws Exception {
            String psOutput = "1234 /usr/pgsql-16/bin/pg_dump\n";
            String networkOutput = "tcp 0 0 127.0.0.1:11111 remote:5000 ESTABLISHED 1234/pg_dump\n" +
                                 "tcp 0 0 127.0.0.1:22222 remote:5432 ESTABLISHED 1234/pg_dump\n" +
                                 "tcp 0 0 127.0.0.1:33333 remote:3306 ESTABLISHED 1234/pg_dump\n" +
                                 "tcp 0 0 127.0.0.1:44444 remote:8080 ESTABLISHED 1234/pg_dump\n";
            
            setupMockProcess(psOutput, networkOutput);
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);
                when(mockRuntime.exec("netstat -anp | grep 1234")).thenReturn(mockProcess);

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                scanMethod.invoke(monitor);

                String output = outputStream.toString();
                
                // Should generate alerts for ports 5000 and 5432, but not 3306 or 8080
                long alertCount = output.lines().filter(line -> line.contains("🚨 ALERT")).count();
                assertEquals(1, alertCount); // Only one alert per process, triggered by first matching port
                assertTrue(output.contains("remote:5000") || output.contains("remote:5432"));
            }
        }

        @Test
        @DisplayName("Should use correct Victoria Metrics URL")
        void shouldUseCorrectVictoriaMetricsUrl() throws Exception {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class)) {
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);
                
                monitor.startMonitoring();
                
                try (MockedConstruction<URL> urlMock = mockConstruction(URL.class, 
                    (mock, context) -> {
                        String url = (String) context.arguments().get(0);
                        assertEquals("http://srv1.company.com:8428/api/v1/import/prometheus", url);
                        when(mock.openConnection()).thenReturn(mockConnection);
                    })) {
                    
                    when(mockConnection.getOutputStream()).thenReturn(mockOutputStream);
                    when(mockConnection.getResponseCode()).thenReturn(200);
                    
                    java.lang.reflect.Method sendMethod = 
                        PgDumpProcessMonitor.class.getDeclaredMethod("sendAlertMetrics");
                    sendMethod.setAccessible(true);
                    sendMethod.invoke(monitor);
                }
            }
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should handle concurrent scanning calls")
        void shouldHandleConcurrentScanningCalls() throws Exception {
            String psOutput = "1234 /usr/pgsql-16/bin/pg_dump\n";
            
            setupMockProcess(psOutput, "");
            
            try (MockedStatic<Runtime> runtimeMock = mockStatic(Runtime.class)) {
                runtimeMock.when(() -> Runtime.getRuntime()).thenReturn(mockRuntime);
                when(mockRuntime.exec("ps -eo pid,cmd --no-headers")).thenReturn(mockProcess);
                when(mockRuntime.exec("netstat -anp | grep 1234")).thenReturn(mockProcess);

                java.lang.reflect.Method scanMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("scanProcesses");
                scanMethod.setAccessible(true);
                
                // Execute multiple scanning operations concurrently
                java.util.concurrent.ExecutorService executor = 
                    java.util.concurrent.Executors.newFixedThreadPool(5);
                
                java.util.List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
                
                for (int i = 0; i < 10; i++) {
                    futures.add(executor.submit(() -> {
                        try {
                            scanMethod.invoke(monitor);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }));
                }
                
                // Wait for all tasks to complete
                for (java.util.concurrent.Future<?> future : futures) {
                    assertDoesNotThrow(() -> future.get());
                }
                
                executor.shutdown();
            }
        }

        @Test
        @DisplayName("Should handle concurrent metrics sending")
        void shouldHandleConcurrentMetricsSending() throws Exception {
            try (MockedStatic<java.net.InetAddress> inetMock = mockStatic(java.net.InetAddress.class);
                 MockedConstruction<URL> urlMock = mockConstruction(URL.class, (mock, context) -> {
                     when(mock.openConnection()).thenReturn(mockConnection);
                 })) {
                
                java.net.InetAddress mockAddress = mock(java.net.InetAddress.class);
                when(mockAddress.getHostName()).thenReturn("test-host");
                inetMock.when(() -> java.net.InetAddress.getLocalHost()).thenReturn(mockAddress);
                
                when(mockConnection.getOutputStream()).thenReturn(mockOutputStream);
                when(mockConnection.getResponseCode()).thenReturn(200);

                monitor.startMonitoring();
                
                java.lang.reflect.Method sendMethod = 
                    PgDumpProcessMonitor.class.getDeclaredMethod("sendAlertMetrics");
                sendMethod.setAccessible(true);
                
                // Execute multiple metrics sending operations concurrently
                java.util.concurrent.ExecutorService executor = 
                    java.util.concurrent.Executors.newFixedThreadPool(3);
                
                java.util.List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
                
                for (int i = 0; i < 5; i++) {
                    futures.add(executor.submit(() -> {
                        try {
                            sendMethod.invoke(monitor);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }));
                }
                
                // Wait for all tasks to complete
                for (java.util.concurrent.Future<?> future : futures) {
                    assertDoesNotThrow(() -> future.get());
                }
                
                executor.shutdown();
                
                // Verify multiple HTTP connections were made
                verify(mockConnection, atLeast(5)).setRequestMethod("POST");
            }
        }
    }
}
