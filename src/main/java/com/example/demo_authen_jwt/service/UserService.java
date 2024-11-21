package com.example.demo_authen_jwt.service;

import com.example.demo_authen_jwt.dto.request.user.UserRequest;
import com.example.demo_authen_jwt.dto.response.UserResponse;
import com.example.demo_authen_jwt.entity.User;

import java.util.List;

public interface UserService {
  UserResponse create(UserRequest request);

  UserResponse detail(String id);

  List<UserResponse> findAll();

  User findByUserName(String username);

  User findById(String id);


}
