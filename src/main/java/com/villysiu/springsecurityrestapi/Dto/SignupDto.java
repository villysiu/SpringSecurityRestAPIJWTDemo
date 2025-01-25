package com.villysiu.springsecurityrestapi.Dto;

import lombok.Data;

@Data
public class SignupDto {
    private String name;
    private String email;
    private String password;
}
