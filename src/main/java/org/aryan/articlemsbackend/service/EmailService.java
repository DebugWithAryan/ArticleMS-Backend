package org.aryan.articlemsbackend.service;



import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    @Value("${app.email.from}")
    private String fromEmail;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Value("${app.email.enabled:true}")
    private boolean emailEnabled;

    @Value("${spring.application.name:Article Management System}")
    private String appName;

    /**
     * Send verification email with retry mechanism
     */
    @Async
    @Retryable(
            retryFor = {MailException.class, MessagingException.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 2000, multiplier = 2)
    )
    public void sendVerificationEmail(String to, String name, String token) {
        log.info("📧 Preparing to send verification email to: {}", to);

        if (!emailEnabled) {
            return;
        }

        try {
            String verificationLink = frontendUrl + "/verify-email?token=" + token;

            Map<String, Object> variables = Map.of(
                    "name", name,
                    "verificationLink", verificationLink,
                    "appName", appName,
                    "token", token
            );

            sendHtmlEmail(
                    to,
                    "Verify Your Email - " + appName,
                    "email-verification",
                    variables
            );

            log.info("✅ Verification email sent successfully to: {}", to);

        } catch (Exception e) {
            log.error("❌ Failed to send verification email to: {} - Error: {}", to, e.getMessage());
            throw new RuntimeException("Failed to send verification email", e);
        }
    }


    @Async
    @Retryable(
            retryFor = {MailException.class, MessagingException.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 2000, multiplier = 2)
    )
    public void sendWelcomeEmail(String to, String name) {
        log.info("📧 Preparing to send welcome email to: {}", to);

        if (!emailEnabled) {
            log.info("Email disabled. Welcome email would be sent to: {}", to);
            return;
        }

        try {
            String loginLink = frontendUrl + "/login";

            Map<String, Object> variables = Map.of(
                    "name", name,
                    "loginLink", loginLink,
                    "appName", appName
            );

            sendHtmlEmail(
                    to,
                    "Welcome to " + appName,
                    "welcome-email",
                    variables
            );

            log.info("✅ Welcome email sent successfully to: {}", to);

        } catch (Exception e) {
            log.error("❌ Failed to send welcome email to: {}", to, e);
            // Don't throw exception for welcome emails - it's not critical
        }
    }


    @Async
    @Retryable(
            retryFor = {MailException.class, MessagingException.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 2000, multiplier = 2)
    )
    public void sendPasswordResetEmail(String to, String name, String token) {
        log.info("📧 Preparing to send password reset email to: {}", to);

        if (!emailEnabled) {
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

            sendHtmlEmail(
                    to,
                    "Reset Your Password - " + appName,
                    "password-reset",
                    variables
            );

            log.info("✅ Password reset email sent successfully to: {}", to);

        } catch (Exception e) {
            log.error("❌ Failed to send password reset email to: {}", to, e);
            throw new RuntimeException("Failed to send password reset email", e);
        }
    }


    private void sendHtmlEmail(String to, String subject, String templateName,
                               Map<String, Object> variables) throws MessagingException {

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        // Set email headers
        helper.setFrom(fromEmail);
        helper.setTo(to);
        helper.setSubject(subject);

        // Add custom headers for SendGrid
        message.addHeader("X-Priority", "1");
        message.addHeader("Importance", "High");

        // Process Thymeleaf template
        Context context = new Context();
        context.setVariables(variables);
        String htmlContent = templateEngine.process(templateName, context);

        helper.setText(htmlContent, true);

        // Send email through SendGrid SMTP
        mailSender.send(message);

        log.debug("Email sent via SendGrid SMTP to: {}", to);
    }


}