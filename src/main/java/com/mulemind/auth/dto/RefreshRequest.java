package com.mulemind.auth.dto;

import lombok.Data;

@Data
public class RefreshRequest {
    private String refreshToken;
}
