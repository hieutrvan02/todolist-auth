package com.example.auth.controller;

import com.example.auth.dto.*;
import com.example.auth.entity.User;
import com.example.auth.service.AuthenticationService;
import com.example.auth.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register (
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> register (
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyEmail(
            @RequestParam("token") String token
    ) {
        authenticationService.verifyToken(token);
        return ResponseEntity.ok("Email verified successfully");
    }

    @PostMapping("/request-token")
    public ResponseEntity<RequestTokenResponse> requestToken(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.requestToken(request));
    }

    @PostMapping("/exchange-token")
    public ResponseEntity<AuthenticationResponse> exchangeToken(
            @RequestBody TokenExchangeRequest request
    ) {
        return ResponseEntity.ok(authenticationService.exchangeToken(request));
    }

    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
        }
        String token = authHeader.substring(7);

        try {
            // will throw if invalid/expired or if it's a request token
            Jws<Claims> jws = jwtService.validateAccessToken(token);
            Claims claims = jws.getBody();
            String email = claims.getSubject();
            User user = authenticationService
                    .getUserByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            return ResponseEntity.ok(Map.of(
                    "valid", true,
                    "userId", user.getId(),
                    "email", user.getEmail(),
                    "role", user.getRole()
            ));
        } catch (JwtException | UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired access token");
        }
    }

}
