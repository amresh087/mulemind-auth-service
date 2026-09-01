package com.mulemind.auth.util;

import java.security.Key;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    @Value("${jwt.refreshExpiration:604800000}")
    private long refreshExpiration;

    private Key getKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateToken(String username, Long userId, Long tenantId, List<String> roles) {
        return buildToken(username, userId, tenantId, roles, expiration);
    }

    public String generateRefreshToken(String username, Long userId, Long tenantId, List<String> roles) {
        return buildToken(username, userId, tenantId, roles, refreshExpiration);
    }

    public String generateToken(String username, String role) {
        return generateToken(username, null, null, role == null ? List.of() : List.of(role));
    }

    public String generateRefreshToken(String username, String role) {
        return generateRefreshToken(username, null, null, role == null ? List.of() : List.of(role));
    }

    private String buildToken(String username, Long userId, Long tenantId, List<String> roles, long ttl) {
        List<String> normalizedRoles = roles == null ? new ArrayList<>() : new ArrayList<>(roles);
        return Jwts.builder()
                .setSubject(username)
                .claim("userId", userId)
                .claim("tenantId", tenantId)
                .claim("username", username)
                .claim("roles", normalizedRoles)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ttl))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims validate(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
