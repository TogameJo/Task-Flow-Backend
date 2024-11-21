package com.example.demo_authen_jwt.exception.user;

import com.example.demo_authen_jwt.exception.base.ConflictException;

public class EmailAlreadyExistException extends ConflictException {
  public EmailAlreadyExistException() {
    super("com.example.demo_authen_jwt.exception.user.EmailAlreadyExistException");
  }
}
