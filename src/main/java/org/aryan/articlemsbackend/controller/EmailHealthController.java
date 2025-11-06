package org.aryan.articlemsbackend.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/health")
@Slf4j
public class EmailHealthController {

    @Value("${sendgrid.api.key:not-configured}")
    private String sendGridApiKey;

    @Value("${app.email.from:not-configured}")
    private String emailFrom;

    @Value("${app.email.enabled:false}")
    private boolean emailEnabled;

    @Value("${app.frontend.url:not-configured}")
    private String frontendUrl;

    @GetMapping("/email")
    public ResponseEntity<Map<String, Object>> checkEmailHealth() {
        Map<String, Object> health = new HashMap<>();

        health.put("provider", "SendGrid Web API");
        health.put("enabled", emailEnabled);
        health.put("method", "HTTPS (Port 443)");
        health.put("from", maskEmail(emailFrom));
        health.put("frontendUrl", frontendUrl);

        if (emailEnabled) {
            if (sendGridApiKey != null && sendGridApiKey.startsWith("SG.")) {
                health.put("status", "ACTIVE");
                health.put("apiKeySet", true);
                health.put("message", "SendGrid Web API is configured and ready");
            } else {
                health.put("status", "MISCONFIGURED");
                health.put("apiKeySet", false);
                health.put("message", "SendGrid API key is missing or invalid");
            }
        } else {
            health.put("status", "DISABLED");
            health.put("message", "Email service is disabled (app.email.enabled=false)");
        }

        return ResponseEntity.ok(health);
    }

    private String maskEmail(String email) {
        if (email == null || email.equals("not-configured")) {
            return "not-configured";
        }

        int atIndex = email.indexOf("@");
        if (atIndex > 2) {
            String prefix = email.substring(0, 2);
            String suffix = email.substring(atIndex);
            return prefix + "***" + suffix;
        }
        return "***";
    }
}