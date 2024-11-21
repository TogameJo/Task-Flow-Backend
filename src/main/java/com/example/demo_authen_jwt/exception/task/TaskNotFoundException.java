package com.example.demo_authen_jwt.exception.task;

import com.example.demo_authen_jwt.exception.base.NotFoundException;

public class TaskNotFoundException extends NotFoundException {
  public TaskNotFoundException() {
    super("com.example.demo_authen_jwt.exception.task.TaskNotFoundException");
  }
}
