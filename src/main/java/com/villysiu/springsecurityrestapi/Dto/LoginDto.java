package com.villysiu.springsecurityrestapi.Dto;

import lombok.Data;

@Data
public class LoginDto {
    private String email;
    private String password;
}