package com.example.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RequestTokenResponse {
    private String requestToken;
}
