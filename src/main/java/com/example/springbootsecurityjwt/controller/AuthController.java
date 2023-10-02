package com.example.springbootsecurityjwt.controller;

import com.example.springbootsecurityjwt.exception.RefreshTokenException;
import com.example.springbootsecurityjwt.model.RefreshToken;
import com.example.springbootsecurityjwt.payload.request.LoginRequest;
import com.example.springbootsecurityjwt.payload.request.RefreshTokenRequest;
import com.example.springbootsecurityjwt.payload.request.SignupRequest;
import com.example.springbootsecurityjwt.payload.response.JwtResponse;
import com.example.springbootsecurityjwt.payload.response.MessageResponse;
import com.example.springbootsecurityjwt.payload.response.RefreshTokenResponse;
import com.example.springbootsecurityjwt.security.jwt.JwtUtils;
import com.example.springbootsecurityjwt.security.service.RefreshTokenService;
import com.example.springbootsecurityjwt.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signin")
    public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        return authService.authenticateUser(loginRequest);
    }

    @PostMapping("/signup")
    public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return authService.registerUser(signUpRequest);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request);
    }
}