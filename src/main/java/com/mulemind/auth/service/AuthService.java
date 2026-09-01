package com.mulemind.auth.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.mulemind.auth.client.UserClient;
import com.mulemind.auth.dto.AuthResponse;
import com.mulemind.auth.dto.AuthValidationResponse;
import com.mulemind.auth.dto.LoginRequest;
import com.mulemind.auth.dto.UserDto;
import com.mulemind.auth.util.JwtUtil;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserClient userClient;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public AuthResponse login(LoginRequest request) {

        UserDto user = userClient.getByUsername(request.getUsername());

        if (user == null || !passwordMatches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        if (!Boolean.TRUE.equals(user.getActive())) {
            throw new RuntimeException("User inactive");
        }

        List<String> roles = resolveRoles(user);
        Long userId = resolveUserId(user);
        Long tenantId = user.getTenantId();

        String token = jwtUtil.generateToken(user.getUsername(), userId, tenantId, roles);
        String refresh = jwtUtil.generateRefreshToken(user.getUsername(), userId, tenantId, roles);

        return AuthResponse.builder()
                .token(token)
                .refreshToken(refresh)
                .username(user.getUsername())
                .role(roles.isEmpty() ? null : roles.get(0))
                .userId(userId)
                .tenantId(tenantId)
                .roles(roles)
                .build();
    }

    public AuthResponse refreshToken(String refreshToken) {
        try {
            Claims claims = jwtUtil.validate(refreshToken);
            String username = claims.getSubject();
            Long userId = getLongClaim(claims, "userId");
            Long tenantId = getLongClaim(claims, "tenantId");
            List<String> roles = extractRoles(claims);

            String newToken = jwtUtil.generateToken(username, userId, tenantId, roles);
            String newRefresh = jwtUtil.generateRefreshToken(username, userId, tenantId, roles);
            return AuthResponse.builder()
                    .token(newToken)
                    .refreshToken(newRefresh)
                    .username(username)
                    .role(roles.isEmpty() ? null : roles.get(0))
                    .userId(userId)
                    .tenantId(tenantId)
                    .roles(roles)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Invalid refresh token");
        }
    }

    public AuthValidationResponse validateToken(String token) {
        try {
            Claims claims = jwtUtil.validate(token);
            List<String> roles = extractRoles(claims);

            return new AuthValidationResponse(
                    true,
                    claims.getSubject(),
                    roles,
                    getLongClaim(claims, "userId"),
                    getLongClaim(claims, "tenantId"));

        } catch (Exception e) {
            return new AuthValidationResponse(false, null, null, null, null);
        }
    }

    private boolean passwordMatches(String rawPassword, String storedPassword) {
        if (storedPassword == null || rawPassword == null) {
            return false;
        }

        if (storedPassword.startsWith("$2a$") || storedPassword.startsWith("$2b$") || storedPassword.startsWith("$2y$")) {
            return passwordEncoder.matches(rawPassword, storedPassword);
        }

        return storedPassword.equals(rawPassword);
    }

    private List<String> resolveRoles(UserDto user) {
        if (user.getRoles() != null && !user.getRoles().isEmpty()) {
            return new ArrayList<>(user.getRoles());
        }
        if (user.getRoleName() != null && !user.getRoleName().isBlank()) {
            return List.of(user.getRoleName());
        }
        if (user.getRole() != null && !user.getRole().isBlank()) {
            return List.of(user.getRole());
        }
        return List.of();
    }

    private Long resolveUserId(UserDto user) {
        if (user.getUserId() != null) {
            return user.getUserId();
        }
        if (user.getId() != null) {
            return user.getId();
        }
        return null;
    }

    private List<String> extractRoles(Claims claims) {
        Object rolesClaim = claims.get("roles");
        if (rolesClaim instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        if (rolesClaim instanceof String role) {
            return List.of(role);
        }
        Object roleClaim = claims.get("role");
        if (roleClaim != null) {
            return List.of(String.valueOf(roleClaim));
        }
        return List.of();
    }

    private Long getLongClaim(Claims claims, String claimName) {
        Object value = claims.get(claimName);
        if (value instanceof Number number) {
            return number.longValue();
        }
        return null;
    }
}
