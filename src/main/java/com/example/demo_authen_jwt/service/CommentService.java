package com.example.demo_authen_jwt.service;

import com.example.demo_authen_jwt.dto.request.comment.CommentRequest;
import com.example.demo_authen_jwt.dto.response.CommentResponse;

import java.util.List;

public interface CommentService {
  void create(CommentRequest request);

  List<CommentResponse> findByTaskId(String taskId);
}
