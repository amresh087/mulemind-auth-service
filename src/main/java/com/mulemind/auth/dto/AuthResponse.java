package com.mulemind.auth.dto;

import java.util.List;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthResponse {
    private String token;
    private String username;
    private String role;
    private Long userId;
    private Long tenantId;
    private List<String> roles;
    private String refreshToken;
}
