if (isTrustedProcess(process)) {
    logger.debug("Skipping trusted process: PID=" + process.getPid() + ", Command=" + process.getCommand());
    continue;
}
