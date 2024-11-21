package com.example.demo_authen_jwt.utils;


import com.example.demo_authen_jwt.exception.authenticate.PasswordIncorrectException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordEncoderUtils {
  public static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();
  public static PasswordEncoder getPasswordEncoder() {
    return PASSWORD_ENCODER;
  }

  public static void equalPassword(String passwordRaw, String passwordEncrypted) {
    if (!getPasswordEncoder().matches(passwordRaw, passwordEncrypted)) {
      throw new PasswordIncorrectException();
    }
  }

}
