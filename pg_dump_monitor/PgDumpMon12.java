package com.security.pgdump.monitor;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class PgDumpProcessMonitor {
    private static final String[] PG_DUMP_PATHS = {
        "/usr/pgsql-16/bin/pg_dump",
        "pg_dump",
        "/bin/pg_dump",
        "/etc/alternative/pgsql-pg_dump"
    };
    private static final int[] MONITORED_PORTS = {5000, 5432};
    private static final long MONITORING_INTERVAL = 1000; // 1 second
    private static final String VICTORIA_METRICS_URL = "http://srv1.company.com:8428/api/v1/import/prometheus";
    
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private String hostname;
    private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    

    public void startMonitoring() {
        try {
            hostname = java.net.InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            hostname = "unknown";
        }
        
        log("INFO", "Starting pg_dump monitoring on host: " + hostname);
        scheduler.scheduleAtFixedRate(this::scanProcesses, 0, MONITORING_INTERVAL, TimeUnit.MILLISECONDS);
    }
    
    private void sendAlertMetrics() {
        try {
            // Отправляем единственную метрику с таймштампом
            String metrics = String.format(
                "pg_dump_monitor_alert_active{host=\"%s\"} 1 %d",
                hostname,
                System.currentTimeMillis() / 1000
            );

            // Создаем HTTP соединение
            URL url = new URL(VICTORIA_METRICS_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            
            // Отправляем данные
            try (OutputStream os = conn.getOutputStream()) {
                os.write(metrics.getBytes());
                os.flush();
            }
            
            // Проверяем ответ
            int responseCode = conn.getResponseCode();
            if (responseCode != 204 && responseCode != 200) {
                log("ERROR", "Failed to send metrics. Response code: " + responseCode);
            }
            
            conn.disconnect();
        } catch (Exception e) {
            log("ERROR", "Error sending metrics: " + e.getMessage());
        }
    }
	
    private void scanProcesses() {
        try {
            Process proc = Runtime.getRuntime().exec("ps -eo pid,cmd --no-headers");
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    for (String pgDumpPath : PG_DUMP_PATHS) {
                        if (line.contains(pgDumpPath)) {
                            String pid = line.trim().split("\\s+")[0];
                            checkNetworkConnections(pid, line);
                            break;
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            log("ERROR", "Error scanning processes: " + e.getMessage());
        }
    }
    
    private void checkNetworkConnections(String pid, String command) {
        try {
            Process proc = Runtime.getRuntime().exec("netstat -anp | grep " + pid);
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("ESTABLISHED")) {
                        for (int port : MONITORED_PORTS) {
                            if (line.contains(":" + port)) {
                                sendAlert(pid, command, line);
                                // Отправляем метрики только при обнаружении алерта
                                sendAlertMetrics();
                                return;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log("ERROR", "Error checking network connections for PID " + pid + ": " + e.getMessage());
        }
    }
    
    private void sendAlert(String pid, String command, String connection) {
        String alert = String.format(
            "🚨 ALERT: pg_dump detected!\n" +
            "PID: %s\n" +
            "Command: %s\n" +
            "Connection: %s\n" +
            "Time: %s",
            pid, command.trim(), connection.trim(), LocalDateTime.now().format(formatter)
        );
        
        log("ALERT", alert);
    }
    
    private void log(String level, String message) {
        String logEntry = String.format("[%s] [%s] %s", 
            LocalDateTime.now().format(formatter), level, message);
        System.out.println(logEntry);
    }
    
    public void stopMonitoring() {
        log("INFO", "Stopping monitoring...");
        scheduler.shutdown();
    }
    
    public static void main(String[] args) {
        PgDumpProcessMonitor monitor = new PgDumpProcessMonitor();
        
        Runtime.getRuntime().addShutdownHook(new Thread(monitor::stopMonitoring));
        
        monitor.startMonitoring();
        
        try {
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
