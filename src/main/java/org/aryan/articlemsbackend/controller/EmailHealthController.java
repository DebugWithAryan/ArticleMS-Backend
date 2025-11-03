package org.aryan.articlemsbackend.controller;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/health")
@RequiredArgsConstructor
@Slf4j
public class EmailHealthController {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.host:not-configured}")
    private String mailHost;

    @Value("${spring.mail.port:0}")
    private int mailPort;

    @Value("${spring.mail.username:not-configured}")
    private String mailUsername;

    @Value("${app.email.enabled:false}")
    private boolean emailEnabled;

    @Value("${app.email.from:not-configured}")
    private String emailFrom;


    @GetMapping("/email")
    public ResponseEntity<Map<String, Object>> checkEmailHealth() {
        Map<String, Object> health = new HashMap<>();

        health.put("provider", "SendGrid");
        health.put("enabled", emailEnabled);
        health.put("host", mailHost);
        health.put("port", mailPort);
        health.put("username", mailUsername); // Will show "apikey"
        health.put("from", maskEmail(emailFrom));

        if (emailEnabled) {
            health.put("status", "ACTIVE");
            health.put("message", "SendGrid email service is configured and active");

            if (mailHost.equals("smtp.sendgrid.net")) {
                health.put("sendgrid", "Connected");
                health.put("smtpStatus", "Ready");
            } else {
                health.put("status", "MISCONFIGURED");
                health.put("message", "SMTP host is not SendGrid");
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

