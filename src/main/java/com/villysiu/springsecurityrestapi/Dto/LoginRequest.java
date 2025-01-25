package com.villysiu.springsecurityrestapi.Dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String email;
    private String password;
}