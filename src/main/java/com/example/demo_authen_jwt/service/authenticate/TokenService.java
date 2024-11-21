package com.example.demo_authen_jwt.service.authenticate;


import com.example.demo_authen_jwt.dto.request.authenticate.CreateTokenRequest;
import com.example.demo_authen_jwt.enums.TokenType;
import io.jsonwebtoken.Claims;

public interface TokenService {
  String createToken(CreateTokenRequest request);

  String getTokenSubject(String token, TokenType tokenType);

  Boolean validateToken(String token, String usernameLogin, TokenType tokenType);

  Claims extractAllClaims(String token, TokenType tokenType);
}
