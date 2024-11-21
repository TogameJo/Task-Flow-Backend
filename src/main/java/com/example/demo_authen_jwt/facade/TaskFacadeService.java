package com.example.demo_authen_jwt.facade;

import com.example.demo_authen_jwt.dto.request.task.TaskRequest;
import com.example.demo_authen_jwt.dto.response.TaskResponse;
import com.example.demo_authen_jwt.entity.Task;

public interface TaskFacadeService {
  void createTask(TaskRequest request);

  void updateTask(String id,TaskRequest request);

  TaskResponse detail(String id);
}
