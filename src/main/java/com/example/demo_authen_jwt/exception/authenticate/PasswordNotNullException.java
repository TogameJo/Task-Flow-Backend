package com.example.demo_authen_jwt.exception.authenticate;


import com.example.demo_authen_jwt.exception.base.BadRequestException;

public class PasswordNotNullException extends BadRequestException {
  public PasswordNotNullException(){
    super("com.example.demo_authen_jwt.exception.authenticate.PasswordNotNullException");
  }
}
