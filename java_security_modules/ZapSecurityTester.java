package com.saas_security.security_modules;

import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.extension.ascan.*;
import org.zaproxy.zap.model.*;

/**
 * Main ZAP-based Security Tester for SaaS Security Checker
 * Integrates ZAP's comprehensive Java scanning capabilities
 */
public class ZapSecurityTester {
    
    private static final Logger logger = LogManager.getLogger(ZapSecurityTester.class);
    
    // Scanner modules
    private Map<String, AbstractPlugin> scanners;
    private ActiveScanController activeScanController;
    private Map<String, Object> config;
    
    public ZapSecurityTester(Map<String, Object> config) {
        this.config = config;
        this.scanners = new ConcurrentHashMap<>();
        this.activeScanController = new ActiveScanController();
        initializeScanners();
    }
    
    /**
     * Run comprehensive security scan on target URL
     */
    public ScanResult runSecurityScan(String targetUrl, String targetDomain) {
        logger.info("Starting comprehensive ZAP security scan for: " + targetUrl);
        
        ScanResult scanResult = new ScanResult();
        scanResult.setTargetUrl(targetUrl);
        scanResult.setTargetDomain(targetDomain);
        scanResult.setStartTime(new Date());
        
        try {
            // Initialize scan target
            Target scanTarget = createScanTarget(targetUrl, targetDomain);
            
            // Run enabled scanner modules
            Map<String, ModuleResult> moduleResults = new ConcurrentHashMap<>();
            
            // XSS Testing
            if (isTestEnabled("xss_scanner")) {
                ModuleResult xssResult = runXssScanner(scanTarget);
                moduleResults.put("xss_scanner", xssResult);
            }
            
            // SQL Injection Testing
            if (isTestEnabled("sql_injection_scanner")) {
                ModuleResult sqlResult = runSqlInjectionScanner(scanTarget);
                moduleResults.put("sql_injection_scanner", sqlResult);
            }
            
            // Directory Traversal Testing
            if (isTestEnabled("directory_traversal_scanner")) {
                ModuleResult dirResult = runDirectoryTraversalScanner(scanTarget);
                moduleResults.put("directory_traversal_scanner", dirResult);
            }
            
            // Command Injection Testing
            if (isTestEnabled("command_injection_scanner")) {
                ModuleResult cmdResult = runCommandInjectionScanner(scanTarget);
                moduleResults.put("command_injection_scanner", cmdResult);
            }
            
            // File Inclusion Testing
            if (isTestEnabled("file_inclusion_scanner")) {
                ModuleResult fileResult = runFileInclusionScanner(scanTarget);
                moduleResults.put("file_inclusion_scanner", fileResult);
            }
            
            // CSRF Testing
            if (isTestEnabled("csrf_scanner")) {
                ModuleResult csrfResult = runCsrfScanner(scanTarget);
                moduleResults.put("csrf_scanner", csrfResult);
            }
            
            // Information Disclosure Testing
            if (isTestEnabled("information_disclosure_scanner")) {
                ModuleResult infoResult = runInformationDisclosureScanner(scanTarget);
                moduleResults.put("information_disclosure_scanner", infoResult);
            }
            
            // Authentication Testing
            if (isTestEnabled("authentication_scanner")) {
                ModuleResult authResult = runAuthenticationScanner(scanTarget);
                moduleResults.put("authentication_scanner", authResult);
            }
            
            // Session Management Testing
            if (isTestEnabled("session_management_scanner")) {
                ModuleResult sessionResult = runSessionManagementScanner(scanTarget);
                moduleResults.put("session_management_scanner", sessionResult);
            }
            
            // SSL/TLS Testing
            if (isTestEnabled("ssl_tls_scanner")) {
                ModuleResult sslResult = runSslTlsScanner(scanTarget);
                moduleResults.put("ssl_tls_scanner", sslResult);
            }
            
            scanResult.setModuleResults(moduleResults);
            scanResult.setEndTime(new Date());
            scanResult.generateSummary();
            
            logger.info("ZAP security scan completed successfully");
            
        } catch (Exception e) {
            logger.error("ZAP security scan failed", e);
            scanResult.setStatus("error");
            scanResult.setErrorMessage(e.getMessage());
        }
        
        return scanResult;
    }
    
    private Target createScanTarget(String targetUrl, String targetDomain) {
        try {
            URL url = new URL(targetUrl);
            Target target = new Target();
            target.setContextId(0); // Default context
            target.addURL(targetUrl);
            target.setRecurse(true);
            target.setMaxDepth((Integer) config.getOrDefault("max_depth", 2));
            return target;
        } catch (Exception e) {
            logger.error("Failed to create scan target", e);
            return null;
        }
    }
    
    private ModuleResult runXssScanner(Target target) {
        logger.info("Running XSS Scanner");
        XssScanner xssScanner = new XssScanner();
        return executeScanner(xssScanner, target, "XSS Scanner");
    }
    
    private ModuleResult runSqlInjectionScanner(Target target) {
        logger.info("Running SQL Injection Scanner");
        SqlInjectionScanner sqlScanner = new SqlInjectionScanner();
        return executeScanner(sqlScanner, target, "SQL Injection Scanner");
    }
    
    private ModuleResult runDirectoryTraversalScanner(Target target) {
        logger.info("Running Directory Traversal Scanner");
        DirectoryTraversalScanner dirScanner = new DirectoryTraversalScanner();
        return executeScanner(dirScanner, target, "Directory Traversal Scanner");
    }
    
    private ModuleResult runCommandInjectionScanner(Target target) {
        logger.info("Running Command Injection Scanner");
        CommandInjectionScanner cmdScanner = new CommandInjectionScanner();
        return executeScanner(cmdScanner, target, "Command Injection Scanner");
    }
    
    private ModuleResult runFileInclusionScanner(Target target) {
        logger.info("Running File Inclusion Scanner");
        FileInclusionScanner fileScanner = new FileInclusionScanner();
        return executeScanner(fileScanner, target, "File Inclusion Scanner");
    }
    
    private ModuleResult runCsrfScanner(Target target) {
        logger.info("Running CSRF Scanner");
        CsrfScanner csrfScanner = new CsrfScanner();
        return executeScanner(csrfScanner, target, "CSRF Scanner");
    }
    
    private ModuleResult runInformationDisclosureScanner(Target target) {
        logger.info("Running Information Disclosure Scanner");
        InformationDisclosureScanner infoScanner = new InformationDisclosureScanner();
        return executeScanner(infoScanner, target, "Information Disclosure Scanner");
    }
    
    private ModuleResult runAuthenticationScanner(Target target) {
        logger.info("Running Authentication Scanner");
        AuthenticationScanner authScanner = new AuthenticationScanner();
        return executeScanner(authScanner, target, "Authentication Scanner");
    }
    
    private ModuleResult runSessionManagementScanner(Target target) {
        logger.info("Running Session Management Scanner");
        SessionManagementScanner sessionScanner = new SessionManagementScanner();
        return executeScanner(sessionScanner, target, "Session Management Scanner");
    }
    
    private ModuleResult runSslTlsScanner(Target target) {
        logger.info("Running SSL/TLS Scanner");
        SslTlsScanner sslTlsScanner = new SslTlsScanner();
        return executeScanner(sslScanner, target, "SSL/TLS Scanner");
    }
    
    private ModuleResult executeScanner(AbstractPlugin scanner, Target target, String scannerName) {
        ModuleResult result = new ModuleResult();
        result.setScannerName(scannerName);
        result.setStartTime(new Date());
        
        try {
            List<Alert> alerts = new ArrayList<>();
            
            // Configure scanner
            scanner.setContextId(target.getContextId());
            
            // Execute scan
            scanner.scan();
            
            // Collect alerts
            collectScannerAlerts(scanner, alerts);
            
            result.setStatus("success");
            result.setVulnerabilitiesFound(alerts);
            result.setEndTime(new Date());
            
            logger.info("Scanner {} completed successfully", scannerName);
            
        } catch (Exception e) {
            logger.error("Scanner {} failed", scannerName, e);
            result.setStatus("error");
            result.setErrorMessage(e.getMessage());
            result.setEndTime(new Date());
        }
        
        return result;
    }
    
    private void collectScannerAlerts(AbstractPlugin scanner, List<Alert> alerts) {
        // Implementation to collect alerts from scanner
        // This would interface with ZAP's alert management system
    }
    
    private void initializeScanners() {
        logger.info("Initializing ZAP security scanners");
        // Initialize scanner configurations
        // Set up plugin dependencies and configurations
    }
    
    private boolean isTestEnabled(String testName) {
        Map<String, Object> tests = (Map<String, Object>) config.get("tests");
        if (tests == null) return false;
        
        Map<String, Object> zapTests = (Map<String, Object>) tests.get("zap_java_testing");
        if (zapTests == null) return false;
        
        return (Boolean) zapTests.getOrDefault(testName, true);
    }
    
    /**
     * Result class for security scan
     */
    public static class ScanResult {
        private String targetUrl;
        private String targetDomain;
        private Date startTime;
        private Date endTime;
        private String status = "running";
        private String errorMessage;
        private Map<String, ModuleResult> moduleResults;
        private ScanSummary summary;
        
        // Getters and setters
        public String getTargetUrl() { return targetUrl; }
        public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }
        
        public String getTargetDomain() { return targetDomain; }
        public void setTargetDomain(String targetDomain) { this.targetDomain = targetDomain; }
        
        public Date getStartTime() { return startTime; }
        public void setStartTime(Date startTime) { this.startTime = startTime; }
        
        public Date getEndTime() { return endTime; }
        public void setEndTime(Date endTime) { this.endTime = endTime; }
        
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        
        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
        
        public Map<String, ModuleResult> getModuleResults() { return moduleResults; }
        public void setModuleResults(Map<String, ModuleResult> moduleResults) { this.moduleResults = moduleResults; }
        
        public ScanSummary getSummary() { return summary; }
        public void setSummary(ScanSummary summary) { this.summary = summary; }
        
        public void generateSummary() {
            summary = new ScanSummary();
            
            int totalModules = moduleResults.size();
            int totalVulnerabilities = 0;
            Map<String, Integer> severityCounts = new HashMap<>();
            
            for (ModuleResult result : moduleResults.values()) {
                if ("success".equals(result.getStatus())) {
                    for (Alert alert : result.getVulnerabilitiesFound()) {
                        totalVulnerabilities++;
                        String severity = String.valueOf(alert.getRisk());
                        severityCounts.merge(severity, 1, Integer::sum);
                    }
                }
            }
            
            summary.setTotalModules(totalModules);
            summary.setTotalVulnerabilities(totalVulnerabilities);
            summary.setSeverityCounts(severityCounts);
            summary.setScanDuration(endTime.getTime() - startTime.getTime());
        }
    }
    
    /**
     * Result for individual scanner module
     */
    public static class ModuleResult {
        private String scannerName;
        private String status;
        private String errorMessage;
        private List<Alert> vulnerabilitiesFound;
        private Date startTime;
        private Date endTime;
        
        // Getters and setters
        public String getScannerName() { return scannerName; }
        public void setScannerName(String scannerName) { this.scannerName = scannerName; }
        
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        
        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
        
        public List<Alert> getVulnerabilitiesFound() { return vulnerabilitiesFound; }
        public void setVulnerabilitiesFound(List<Alert> vulnerabilitiesFound) { this.vulnerabilitiesFound = vulnerabilitiesFound; }
        
        public Date getStartTime() { return startTime; }
        public void setStartTime(Date startTime) { this.startTime = startTime; }
        
        public Date getEndTime() { return endTime; }
        public void setEndTime(Date endTime) { this.endTime = endTime; }
    }
    
    /**
     * Summary of scan results
     */
    public static class ScanSummary {
        private int totalModules;
        private int totalVulnerabilities;
        private Map<String, Integer> severityCounts;
        private long scanDuration; // milliseconds
        
        // Getters and setters
        public int getTotalModules() { return totalModules; }
        public void setTotalModules(int totalModules) { this.totalModules = totalModules; }
        
        public int getTotalVulnerabilities() { return totalVulnerabilities; }
        public void setTotalVulnerabilities(int totalVulnerabilities) { this.totalVulnerabilities = totalVulnerabilities; }
        
        public Map<String, Integer> getSeverityCounts() { return severityCounts; }
        public void setSeverityCounts(Map<String, Integer> severityCounts) { this.severityCounts = severityCounts; }
        
        public long getScanDuration() { return scanDuration; }
        public void setScanDuration(long scanDuration) { this.scanDuration = scanDuration; }
    }
}
