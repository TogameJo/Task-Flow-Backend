package com.example.demo_authen_jwt.exception.authenticate;


import com.example.demo_authen_jwt.exception.base.BadRequestException;

public class UsernameNotNullException extends BadRequestException {
  public UsernameNotNullException() {
    super("com.example.demo_authen_jwt.exception.authenticate.UsernameNotNullException");
  }
}
