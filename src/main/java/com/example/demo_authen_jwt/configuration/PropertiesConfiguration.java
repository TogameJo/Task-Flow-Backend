package com.example.demo_authen_jwt.configuration;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Getter
@Configuration
public class PropertiesConfiguration {
  @Value("${jwt.access-token.secret-key}")
  private String accessTokenSecretKey;

  @Value("${jwt.access-token.ttl}")
  private Long accessTokenTtl;

  @Value("${jwt.refresh-token.secret-key}")
  private String refreshTokenSecretKey;

  @Value("${jwt.refresh-token.ttl}")
  private Long refreshTokenTtl;
}
