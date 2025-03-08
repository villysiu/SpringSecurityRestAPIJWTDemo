package com.villysiu.springsecurityrestapi.Dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class JwtTokenResponse {
    private String token;
}
