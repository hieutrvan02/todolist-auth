package com.example.auth.service;

import com.example.auth.dto.*;
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
import org.springframework.security.authentication.BadCredentialsException;
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
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .verified(false)
                .build();
        userRepository.save(user);

        String token = UUID.randomUUID().toString();
        var vt = new VerificationToken();
        vt.setToken(token);
        vt.setUser(user);
        vt.setExpiryDate(Instant.now().plus(24, ChronoUnit.HOURS));
        tokenRepository.save(vt);

        eventPublisher.publishUserRegistered(user, token);

        return AuthenticationResponse.builder()
                .message("Registration successful! Please check your email to verify your account.")
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String accessJwt = jwtService.generateAccessToken(user);
        return AuthenticationResponse.builder()
                .token(accessJwt)
                .build();
    }

    public Optional<User> getUserByEmail(String email) {
        logger.debug("Tìm user với email: {}", email);
        return userRepository.findByEmail(email);
    }

    public RequestTokenResponse requestToken(AuthenticationRequest rq) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(rq.getEmail(), rq.getPassword())
        );

        var user = userRepository.findByEmail(rq.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!user.isEnabled()) {
            throw new BadCredentialsException("Email not verified");
        }

        String reqToken = jwtService.generateRequestToken(user);
        return new RequestTokenResponse(reqToken);
    }

    public AuthenticationResponse exchangeToken(TokenExchangeRequest rq) {
        String requestToken = rq.getRequestToken();

        String email = jwtService.extractUsername(requestToken);

        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!jwtService.isRequestTokenValid(requestToken, user)) {
            throw new BadCredentialsException("Invalid or expired request token");
        }

        String accessJwt = jwtService.generateAccessToken(user);
        return AuthenticationResponse.builder()
                .token(accessJwt)
                .build();
    }

    public void verifyToken(String token) {
        VerificationToken vt = tokenRepository
                .findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));

        if (vt.getExpiryDate().isBefore(Instant.now())) {
            throw new RuntimeException("Verification token expired");
        }

        User user = vt.getUser();
        user.setVerified(true);
        userRepository.save(user);

        // Delete the token so it can’t be reused
        tokenRepository.delete(vt);
    }
}
