package com.mulemind.auth.dto;

import java.util.List;

import lombok.Data;

@Data
public class UserDto {
    private Long id;
    private Long userId;
    private Long tenantId;
    private String username;
    private String password;
    private String role;
    private String roleName;
    private List<String> roles;
    private Boolean active;
}
