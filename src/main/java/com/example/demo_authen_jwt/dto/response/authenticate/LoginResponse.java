package com.example.demo_authen_jwt.dto.response.authenticate;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import static com.example.demo_authen_jwt.constant.AuthConstant.JwtConstant.TOKEN_TYPE;


@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record LoginResponse(String id,
                            String accessToken,
                            String refreshToken,
                            long tokenExpiredSeconds,
                            long refreshExpiredSeconds,
                            String tokenType
) {
  public LoginResponse(String id, String accessToken, String refreshToken, long tokenExpiredSeconds, long refreshExpiredSeconds) {
    this(id, accessToken, refreshToken, tokenExpiredSeconds, refreshExpiredSeconds, TOKEN_TYPE);
  }
}


