package org.aryan.articlemsbackend.service;

import com.sendgrid.*;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.io.IOException;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final SpringTemplateEngine templateEngine;

    @Value("${sendgrid.api.key}")
    private String sendGridApiKey;

    @Value("${app.email.from}")
    private String fromEmail;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Value("${app.email.enabled:true}")
    private boolean emailEnabled;

    @Value("${spring.application.name:Article Management System}")
    private String appName;

    @Async
    @Retryable(
            retryFor = {IOException.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 2000, multiplier = 2)
    )
    public void sendVerificationEmail(String to, String name, String token) {
        log.info("📧 Preparing to send verification email to: {}", to);

        if (!emailEnabled) {
            log.warn("Email service is disabled");
            return;
        }

        try {
            String verificationLink = frontendUrl + "/api/auth/verify-email?token=" + token;

            Map<String, Object> variables = Map.of(
                    "name", name,
                    "verificationLink", verificationLink,
                    "appName", appName,
                    "token", token
            );

            String htmlContent = processTemplate("email-verification", variables);

            sendEmail(
                    to,
                    "Verify Your Email - " + appName,
                    htmlContent
            );

            log.info("✅ Verification email sent successfully to: {}", to);

        } catch (Exception e) {
            log.error("❌ Failed to send verification email to: {}", to, e);
            throw new RuntimeException("Failed to send verification email", e);
        }
    }

    @Async
    @Retryable(
            retryFor = {IOException.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 2000, multiplier = 2)
    )
    public void sendWelcomeEmail(String to, String name) {
        log.info("📧 Preparing to send welcome email to: {}", to);

        if (!emailEnabled) {
            log.warn("Email service is disabled");
            return;
        }

        try {
            String loginLink = frontendUrl + "/login";

            Map<String, Object> variables = Map.of(
                    "name", name,
                    "loginLink", loginLink,
                    "appName", appName
            );

            String htmlContent = processTemplate("welcome-email", variables);

            sendEmail(
                    to,
                    "Welcome to " + appName,
                    htmlContent
            );

            log.info("✅ Welcome email sent successfully to: {}", to);

        } catch (Exception e) {
            log.error("❌ Failed to send welcome email to: {}", to, e);
        }
    }

    @Async
    @Retryable(
            retryFor = {IOException.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 2000, multiplier = 2)
    )
    public void sendPasswordResetEmail(String to, String name, String token) {
        log.info("📧 Preparing to send password reset email to: {}", to);

        if (!emailEnabled) {
            log.warn("Email service is disabled");
            return;
        }

        try {
            String resetLink = frontendUrl + "/reset-password?token=" + token;

            Map<String, Object> variables = Map.of(
                    "name", name,
                    "resetLink", resetLink,
                    "appName", appName,
                    "token", token
            );

            String htmlContent = processTemplate("password-reset", variables);

            sendEmail(
                    to,
                    "Reset Your Password - " + appName,
                    htmlContent
            );

            log.info("✅ Password reset email sent successfully to: {}", to);

        } catch (Exception e) {
            log.error("❌ Failed to send password reset email to: {}", to, e);
            throw new RuntimeException("Failed to send password reset email", e);
        }
    }

    private void sendEmail(String to, String subject, String htmlContent) throws IOException {
        log.info("Sending email via SendGrid Web API (HTTPS)...");

        Email from = new Email(fromEmail);
        Email toEmail = new Email(to);
        Content content = new Content("text/html", htmlContent);
        Mail mail = new Mail(from, subject, toEmail, content);

        SendGrid sg = new SendGrid(sendGridApiKey);
        Request request = new Request();

        try {
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());

            Response response = sg.api(request);

            log.info("SendGrid API Response - Status: {}, Body: {}",
                    response.getStatusCode(), response.getBody());

            if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
                log.info("✅ Email sent successfully via SendGrid Web API");
            } else {
                log.error("❌ SendGrid API error: {}", response.getBody());
                throw new IOException("SendGrid API returned error: " + response.getStatusCode());
            }

        } catch (IOException e) {
            log.error("❌ Failed to send email via SendGrid Web API: {}", e.getMessage());
            throw e;
        }
    }

    private String processTemplate(String templateName, Map<String, Object> variables) {
        Context context = new Context();
        context.setVariables(variables);
        return templateEngine.process(templateName, context);
    }
}