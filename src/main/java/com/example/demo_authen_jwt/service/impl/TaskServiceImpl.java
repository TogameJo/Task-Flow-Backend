package com.example.demo_authen_jwt.service.impl;

import com.example.demo_authen_jwt.dto.request.task.TaskRequest;
import com.example.demo_authen_jwt.dto.response.TaskResponse;
import com.example.demo_authen_jwt.entity.Task;
import com.example.demo_authen_jwt.enums.Priority;
import com.example.demo_authen_jwt.enums.StatusTask;
import com.example.demo_authen_jwt.exception.task.TaskNotFoundException;
import com.example.demo_authen_jwt.repositiory.TaskRepository;
import com.example.demo_authen_jwt.service.TaskService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class TaskServiceImpl implements TaskService {

  private final TaskRepository repository;

  @Override
  @Transactional
  public void create(TaskRequest request) {
    Task task = this.toEntity(request);
    repository.save(task);
  }

  @Override
  @Transactional
  public void update(String id, TaskRequest request) {
    Task task = this.find(id);
    this.setProperty(task, request);
    repository.save(task);
  }

  @Override
  public TaskResponse get(String id) {
    return repository.get(id).orElseThrow(TaskNotFoundException::new);
  }

  @Override
  public List<TaskResponse> list(String keyword) {
    return repository.list(keyword == null ? "" : keyword);
  }

  @Override
  public void delete(String id) {
    Task task = this.find(id);
    repository.delete(task);
  }

  private Task toEntity(TaskRequest taskRequest) {
    return new Task(
          taskRequest.getTitle(),
          taskRequest.getDescription(),
          taskRequest.getDate(),
          Priority.fromLevel(taskRequest.getPriority()),
          StatusTask.fromStatusCode(taskRequest.getStatus()),
          taskRequest.getUserId()
    );
  }

  private Task find(String id) {
    return repository.findById(id).orElseThrow(TaskNotFoundException::new);
  }

  private void setProperty(Task task, TaskRequest request) {
    task.setTitle(request.getTitle());
    task.setDescription(request.getDescription());
    task.setDate(request.getDate());
    task.setPriority(Priority.fromLevel(request.getPriority()));
    task.setStatus(StatusTask.fromStatusCode(request.getStatus()));
    task.setUserId(request.getUserId());
  }

}
