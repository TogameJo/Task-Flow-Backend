package com.example.demo_authen_jwt.dto.request.authenticate;



import com.example.demo_authen_jwt.enums.TokenType;

import java.util.Map;

public record CreateTokenRequest (String subject, TokenType tokenType, long expiredSeconds, Map<String, String> data) {
}
