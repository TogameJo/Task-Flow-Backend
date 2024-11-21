package com.example.demo_authen_jwt.exception.authenticate;


import com.example.demo_authen_jwt.exception.base.BadRequestException;

public class PasswordIncorrectException extends BadRequestException {
  private static final String DEFAULT_CODE = "com.example.demo_authen_jwt.exception.authenticate.PasswordIncorrectException";

  public PasswordIncorrectException() {
    super(DEFAULT_CODE);
  }
}
