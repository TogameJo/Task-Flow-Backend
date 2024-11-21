package com.example.demo_authen_jwt.facade.impl;

import com.example.demo_authen_jwt.dto.request.comment.CommentRequest;
import com.example.demo_authen_jwt.facade.CommentFacadeService;
import com.example.demo_authen_jwt.service.CommentService;
import com.example.demo_authen_jwt.service.TaskService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CommentFacadeServiceImpl implements CommentFacadeService {
  private final CommentService commentService;
  private final TaskService taskService;
  @Override
  public void createComment(CommentRequest commentRequest) {
     taskService.get(commentRequest.getTaskId());
     commentService.create(commentRequest);
  }

}
