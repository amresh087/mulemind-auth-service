package com.mulemind.auth.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mulemind.auth.dto.AuthResponse;
import com.mulemind.auth.dto.AuthValidationResponse;
import com.mulemind.auth.dto.LoginRequest;
import com.mulemind.auth.service.AuthService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService service;

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest request) {
        return service.login(request);
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody com.mulemind.auth.dto.RefreshRequest req) {
        return service.refreshToken(req.getRefreshToken());
    }

    @PostMapping("/validate")
    public AuthValidationResponse validate(@RequestHeader("Authorization") String token) {
        AuthValidationResponse res = service.validateToken(token.replace("Bearer ", ""));

        log.info("Auth validation response: {}", res);
        return res;
    }


}
