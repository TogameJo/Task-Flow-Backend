package com.example.demo_authen_jwt.controller;

import com.example.demo_authen_jwt.dto.response.ResponseGeneral;
import com.example.demo_authen_jwt.dto.response.UserResponse;
import com.example.demo_authen_jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static com.example.demo_authen_jwt.constant.AuthConstant.MessageException.SUCCESS;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/users")
public class UserController {
  private final UserService userService;

  @GetMapping("{id}")
  public ResponseGeneral<UserResponse> getUser(
        @PathVariable String id
  ) {

    return ResponseGeneral.ofSuccess(
          SUCCESS,
          userService.detail(id)
    );
  }

  @GetMapping
  public ResponseGeneral<List<UserResponse>> getAllUsers(
  ) {
    return ResponseGeneral.ofSuccess(
          SUCCESS,
          userService.findAll()
    );
  }
}
