package com.mulemind.auth.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import com.mulemind.auth.util.JwtUtil;

import io.jsonwebtoken.Claims;

class JwtUtilTest {

    @Test
    void generateTokenIncludesUserAndTenantClaims() {
        JwtUtil jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "secret", "R9P4zGQkN8w9Z4s8f1xH2bKZPq9nFQX5RrQ8sM1eX2A=");
        ReflectionTestUtils.setField(jwtUtil, "expiration", 3_600_000L);
        ReflectionTestUtils.setField(jwtUtil, "refreshExpiration", 86_400_000L);

        String token = jwtUtil.generateToken("alice", 101L, 42L, List.of("SUPER_ADMIN", "BUSINESS_USER"));

        Claims claims = jwtUtil.validate(token);

        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.get("userId", Long.class)).isEqualTo(101L);
        assertThat(claims.get("tenantId", Long.class)).isEqualTo(42L);
        assertThat(claims.get("username", String.class)).isEqualTo("alice");
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("roles");

        assertThat(roles).hasSize(2);
        assertThat(roles).contains("SUPER_ADMIN", "BUSINESS_USER");
    }
}
