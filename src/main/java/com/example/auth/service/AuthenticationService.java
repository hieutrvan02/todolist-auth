package com.example.auth.service;

import com.example.auth.dto.AuthenticationRequest;
import com.example.auth.dto.AuthenticationResponse;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.example.auth.entity.VerificationToken;
import com.example.auth.messaging.AmqpEventPublisher;
import com.example.auth.repository.UserRepository;
import com.example.auth.repository.VerificationTokenRepository;
import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;    // Thêm import logger Log4j2
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private static final Logger logger = LogManager.getLogger(AuthenticationService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationTokenRepository tokenRepository;
    private final AmqpEventPublisher eventPublisher;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;

    public AuthenticationResponse register(RegisterRequest request) {
        // 1) create user (verified = false by default)
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .verified(false)                                      // ← ensure false
                .build();
        userRepository.save(user);

        // 2) generate & save a one‑time token
        String token = UUID.randomUUID().toString();
        var vt = new VerificationToken();
        vt.setToken(token);
        vt.setUser(user);
        vt.setExpiryDate(Instant.now().plus(24, ChronoUnit.HOURS));
        tokenRepository.save(vt);

        // 3) fire an event so NotificationService can send the email
        eventPublisher.publishUserRegistered(user, token);

        // 4) respond with “check your email” (no full JWT yet)
        return AuthenticationResponse.builder()
                .message("Registration successful! Please check your email to verify your account.")
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        logger.info("Bắt đầu xác thực cho email: {}", request.getEmail());

        // Không log password để tránh lộ thông tin nhạy cảm
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        logger.debug("AuthManager đã xác thực thành công cho email: {}", request.getEmail());

        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    // Log cảnh báo khi user không tồn tại
                    logger.warn("User không tồn tại với email: {}", request.getEmail());
                    return new UsernameNotFoundException("User not found");
                });

        var jwtToken = jwtService.generateToken(user);
        logger.info("User xác thực thành công cho email: {}", request.getEmail());
        logger.debug("JWT token đã được sinh cho user: {}", request.getEmail());

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public Optional<User> getUserByEmail(String email) {
        logger.debug("Tìm user với email: {}", email);
        return userRepository.findByEmail(email);
    }
}
