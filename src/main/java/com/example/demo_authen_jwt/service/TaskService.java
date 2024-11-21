package com.example.demo_authen_jwt.service;

import com.example.demo_authen_jwt.dto.request.task.TaskRequest;
import com.example.demo_authen_jwt.dto.response.TaskResponse;

import java.util.List;

public interface TaskService {
  void create(TaskRequest request);

  void update(String id, TaskRequest request);

  TaskResponse get(String id);

  List<TaskResponse> list(String keyword);

  void delete(String id);

}
