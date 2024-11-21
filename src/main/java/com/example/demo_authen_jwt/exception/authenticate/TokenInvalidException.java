package com.example.demo_authen_jwt.exception.authenticate;


import com.example.demo_authen_jwt.exception.base.UnauthorizedException;

public class TokenInvalidException extends UnauthorizedException {
  public TokenInvalidException() {
    super("com.example.demo_authen_jwt.exception.authenticate.TokenValidException");
  }
}
