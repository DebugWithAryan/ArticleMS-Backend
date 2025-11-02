package org.aryan.articlemsbackend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aryan.articlemsbackend.dto.*;
import org.aryan.articlemsbackend.entity.RefreshToken;
import org.aryan.articlemsbackend.entity.Role;
import org.aryan.articlemsbackend.entity.User;
import org.aryan.articlemsbackend.exception.*;
import org.aryan.articlemsbackend.repo.RefreshTokenRepository;
import org.aryan.articlemsbackend.repo.UserRepository;
import org.aryan.articlemsbackend.security.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Value("${app.email.verification.expiration}")
    private long verificationTokenExpiration;


    @Transactional
    public MessageResponse register(RegisterRequest request) {
        log.info("Attempting to register user: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Registration failed: Email already exists - {}", request.getEmail());
            throw new EmailAlreadyExistsException("Email is already registered");
        }

        String verificationToken = UUID.randomUUID().toString();

        var user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .emailVerified(false)
                .verificationToken(verificationToken)
                .verificationTokenExpiry(
                        LocalDateTime.now().plusSeconds(verificationTokenExpiration / 1000)
                )
                .build();

        userRepository.save(user);
        log.info("User registered successfully: {}", user.getEmail());

        emailService.sendVerificationEmail(
                user.getEmail(),
                user.getName(),
                verificationToken
        );

        return new MessageResponse(
                "Registration successful! Please check your email to verify your account."
        );
    }


    @Transactional
    public AuthResponse verifyEmail(String token) {
        log.info("Attempting to verify email with token");

        User user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> new BadRequestException("Invalid verification token"));

        // Check if token expired
        if (user.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            log.warn("Verification token expired for user: {}", user.getEmail());
            throw new TokenExpiredException("Verification token has expired. Please request a new one.");
        }

        user.setEmailVerified(true);
        user.setVerificationToken(null);
        user.setVerificationTokenExpiry(null);
        userRepository.save(user);

        log.info("Email verified successfully for user: {}", user.getEmail());

        emailService.sendWelcomeEmail(user.getEmail(), user.getName());

        var accessToken = jwtService.generateAccessToken(user);
        var refreshToken = createRefreshToken(user);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .userId(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .message("Email verified successfully! You are now logged in.")
                .build();
    }


    @Transactional
    public MessageResponse resendVerificationEmail(String email) {
        log.info("Resending verification email to: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (user.isEmailVerified()) {
            throw new BadRequestException("Email is already verified");
        }

        String verificationToken = UUID.randomUUID().toString();
        user.setVerificationToken(verificationToken);
        user.setVerificationTokenExpiry(
                LocalDateTime.now().plusSeconds(verificationTokenExpiration / 1000)
        );
        userRepository.save(user);

        emailService.sendVerificationEmail(
                user.getEmail(),
                user.getName(),
                verificationToken
        );

        return new MessageResponse("Verification email sent successfully");
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        log.info("Login attempt for user: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UnauthorizedException("Invalid email or password"));

        if (!user.isAccountNonLocked()) {
            log.warn("Login failed: Account locked - {}", user.getEmail());
            throw new AccountLockedException(
                    "Your account is locked due to multiple failed login attempts. " +
                            "Please try again after 24 hours."
            );
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            if (!user.isEmailVerified()) {
                log.warn("Login failed: Email not verified - {}", user.getEmail());
                throw new EmailNotVerifiedException(
                        "Please verify your email address before logging in"
                );
            }

            user.resetFailedAttempts();
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            refreshTokenRepository.deleteByUser(user);

            var accessToken = jwtService.generateAccessToken(user);
            var refreshToken = createRefreshToken(user);

            log.info("User logged in successfully: {}", user.getEmail());

            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken.getToken())
                    .userId(user.getId())
                    .email(user.getEmail())
                    .name(user.getName())
                    .build();

        } catch (Exception e) {
            // Increment failed attempts
            user.incrementFailedAttempts();
            userRepository.save(user);
            log.warn("Failed login attempt for user: {}", user.getEmail());
            throw new UnauthorizedException("Invalid email or password");
        }
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        log.info("Attempting to refresh token");

        var refreshToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

        if (refreshToken.isExpired()) {
            refreshTokenRepository.delete(refreshToken);
            log.warn("Refresh token expired");
            throw new TokenExpiredException("Refresh token has expired. Please login again.");
        }

        var user = refreshToken.getUser();
        var accessToken = jwtService.generateAccessToken(user);

        log.info("Token refreshed successfully for user: {}", user.getEmail());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .userId(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .build();
    }

    @Transactional
    public MessageResponse requestPasswordReset(PasswordResetRequest request) {
        log.info("Password reset requested for: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Generate reset token
        String resetToken = UUID.randomUUID().toString();
        user.setPasswordResetToken(resetToken);
        user.setPasswordResetTokenExpiry(LocalDateTime.now().plusHours(1));
        userRepository.save(user);

        // Send email
        emailService.sendPasswordResetEmail(
                user.getEmail(),
                user.getName(),
                resetToken
        );

        return new MessageResponse("Password reset link sent to your email");
    }


    @Transactional
    public MessageResponse resetPassword(String token, String newPassword) {
        log.info("Attempting to reset password");

        User user = userRepository.findByPasswordResetToken(token)
                .orElseThrow(() -> new BadRequestException("Invalid reset token"));

        if (user.getPasswordResetTokenExpiry().isBefore(LocalDateTime.now())) {
            log.warn("Password reset token expired for user: {}", user.getEmail());
            throw new TokenExpiredException("Reset token has expired. Please request a new one.");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);
        user.resetFailedAttempts();
        userRepository.save(user);

        // Invalidate all refresh tokens
        refreshTokenRepository.deleteByUser(user);

        log.info("Password reset successfully for user: {}", user.getEmail());

        return new MessageResponse("Password reset successfully. Please login with your new password.");
    }


    @Transactional
    public MessageResponse logout(String email) {
        log.info("User logging out: {}", email);

        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        refreshTokenRepository.deleteByUser(user);

        return new MessageResponse("Logged out successfully");
    }


    private RefreshToken createRefreshToken(User user) {
        var refreshToken = RefreshToken.builder()
                .user(user)
                .token(jwtService.generateRefreshToken(user))
                .expiryDate(Instant.now().plusMillis(refreshTokenExpiration))
                .build();

        return refreshTokenRepository.save(refreshToken);
    }
}

