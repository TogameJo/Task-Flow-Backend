package com.example.demo_authen_jwt.facade.impl;

import com.example.demo_authen_jwt.dto.request.task.TaskRequest;
import com.example.demo_authen_jwt.dto.response.TaskResponse;
import com.example.demo_authen_jwt.facade.TaskFacadeService;
import com.example.demo_authen_jwt.service.CommentService;
import com.example.demo_authen_jwt.service.TaskService;
import com.example.demo_authen_jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TaskFacadeServiceImpl implements TaskFacadeService {
  private final TaskService taskService;
  private final UserService userService;
  private final CommentService commentService;

  @Override
  public void createTask(TaskRequest request) {
    userService.detail(request.getUserId());
    taskService.create(request);
  }

  @Override
  public void updateTask(String id, TaskRequest request) {
    userService.detail(request.getUserId());
    taskService.update(id, request);
  }

  @Override
  public TaskResponse detail(String id) {
    TaskResponse response = taskService.get(id);
    response.setComments(commentService.findByTaskId(id));
    return response;
  }
}
