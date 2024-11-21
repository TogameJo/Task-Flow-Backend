package com.example.demo_authen_jwt.controller;

import com.example.demo_authen_jwt.dto.request.user.UserRequest;
import com.example.demo_authen_jwt.dto.request.authenticate.LoginRequest;
import com.example.demo_authen_jwt.dto.request.authenticate.RefreshTokenRequest;
import com.example.demo_authen_jwt.dto.response.ResponseGeneral;
import com.example.demo_authen_jwt.dto.response.UserResponse;
import com.example.demo_authen_jwt.dto.response.authenticate.LoginResponse;
import com.example.demo_authen_jwt.facade.AuthenticateFacadeService;
import com.example.demo_authen_jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import static com.example.demo_authen_jwt.constant.AuthConstant.MessageException.SUCCESS;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/auth")
@CrossOrigin("*")
public class AuthController {
  private final AuthenticateFacadeService authenticateFacadeService;
  private final UserService userService;

  @PostMapping("/login")
  public ResponseGeneral<LoginResponse> login(
        @RequestBody LoginRequest request
  ) {

    return ResponseGeneral.ofSuccess(
          SUCCESS,
          authenticateFacadeService.login(request));
  }

  @PostMapping("/refresh")
  public ResponseGeneral<LoginResponse> refresh(
        @RequestBody RefreshTokenRequest request
  ) {

    return ResponseGeneral.ofSuccess(
          SUCCESS,
          authenticateFacadeService.refreshToken(request));
  }


  @PostMapping("/register")
  public ResponseGeneral<UserResponse> register(
        @RequestBody UserRequest request
  ) {

    return ResponseGeneral.ofCreated(
          SUCCESS,
          userService.create(request)
    );
  }

}
