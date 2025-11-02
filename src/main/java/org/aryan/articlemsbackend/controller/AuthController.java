package org.aryan.articlemsbackend.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.aryan.articlemsbackend.dto.*;
import org.aryan.articlemsbackend.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @PostMapping("/register")
    public ResponseEntity<MessageResponse> register(
            @Valid @RequestBody RegisterRequest request) {
        MessageResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }


    @GetMapping("/verify-email")
    public ResponseEntity<AuthResponse> verifyEmail(@RequestParam String token) {
        AuthResponse response = authService.verifyEmail(token);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/resend-verification")
    public ResponseEntity<MessageResponse> resendVerification(
            @Valid @RequestBody ResendVerificationRequest request) {
        MessageResponse response = authService.resendVerificationEmail(request.getEmail());
        return ResponseEntity.ok(response);
    }


    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/forgot-password")
    public ResponseEntity<MessageResponse> forgotPassword(
            @Valid @RequestBody PasswordResetRequest request) {
        MessageResponse response = authService.requestPasswordReset(request);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/reset-password")
    public ResponseEntity<MessageResponse> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        MessageResponse response = authService.resetPassword(
                request.getToken(),
                request.getNewPassword()
        );
        return ResponseEntity.ok(response);
    }


    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(Authentication authentication) {
        String email = authentication.getName();
        MessageResponse response = authService.logout(email);
        return ResponseEntity.ok(response);
    }
}