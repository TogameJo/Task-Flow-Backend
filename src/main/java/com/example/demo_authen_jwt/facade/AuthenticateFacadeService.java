package com.example.demo_authen_jwt.facade;

import com.example.demo_authen_jwt.dto.request.authenticate.LoginRequest;
import com.example.demo_authen_jwt.dto.request.authenticate.RefreshTokenRequest;
import com.example.demo_authen_jwt.dto.response.authenticate.LoginResponse;

public interface AuthenticateFacadeService {
  LoginResponse login(LoginRequest request);

  LoginResponse refreshToken(RefreshTokenRequest request);
}
