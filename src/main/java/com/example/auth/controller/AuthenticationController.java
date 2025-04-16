package com.example.auth.controller;

import com.example.auth.dto.AuthenticationRequest;
import com.example.auth.dto.AuthenticationResponse;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.service.AuthenticationService;
import com.example.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        // Kiểm tra header có tồn tại và có định dạng hợp lệ (có tiền tố "Bearer ")
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
        }

        // Loại bỏ tiền tố "Bearer " để lấy token thật
        String token = authHeader.substring(7);

        try {
            String userEmail = jwtService.extractUsername(token);

            var user = authenticationService
                    .getUserByEmail(userEmail)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            boolean valid = jwtService.isTokenValid(token, user);

            if (!valid) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token invalid or expired");
            }

            return ResponseEntity.ok(
                    Map.of(
                            "valid", true,
                            "userId", user.getId(),
                            "email", user.getEmail(),
                            "role", user.getRole()
                    )
            );
        } catch (Exception e) {
            // Bắt các lỗi parse token, token sai định dạng, v.v.
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }
    }


}
