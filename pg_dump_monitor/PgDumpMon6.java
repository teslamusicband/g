private boolean isTrustedProcess(ProcessInfo process) {
    if (process.getCommand() == null) return false;
    
    // Исключаем pg_dump из доверенных процессов
    if (process.getCommand().contains("pg_dump")) {
        return false;
    }
    
    return trustedProcesses.stream().anyMatch(process.getCommand()::contains);
}
