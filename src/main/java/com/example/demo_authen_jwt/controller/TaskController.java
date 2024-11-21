package com.example.demo_authen_jwt.controller;

import com.example.demo_authen_jwt.dto.request.task.TaskRequest;
import com.example.demo_authen_jwt.dto.response.ResponseGeneral;
import com.example.demo_authen_jwt.dto.response.TaskResponse;
import com.example.demo_authen_jwt.facade.TaskFacadeService;
import com.example.demo_authen_jwt.service.MessageService;
import com.example.demo_authen_jwt.service.TaskService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static com.example.demo_authen_jwt.constant.AuthConstant.MessageException.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/tasks")
public class TaskController {

  private final TaskService taskService;
  private final TaskFacadeService taskFacadeService;
  private final MessageService messageService;

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public ResponseGeneral<Void> create(
        @RequestBody TaskRequest request,
        @RequestHeader(name = LANGUAGE, defaultValue = DEFAULT_LANGUAGE) String language
  ) {

    taskFacadeService.createTask(request);
    return ResponseGeneral.ofSuccess(
          messageService.getMessage(SUCCESS, language)
    );
  }

  @PutMapping("{id}")
  public ResponseGeneral<Void> update(
        @PathVariable String id,
        @RequestBody TaskRequest request,
        @RequestHeader(name = LANGUAGE, defaultValue = DEFAULT_LANGUAGE) String language
  ) {

    taskFacadeService.updateTask(id, request);
    return ResponseGeneral.ofSuccess(
          messageService.getMessage(SUCCESS, language)
    );
  }

  @DeleteMapping("{id}")
  public ResponseGeneral<Void> delete(
        @PathVariable String id,
        @RequestHeader(name = LANGUAGE, defaultValue = DEFAULT_LANGUAGE) String language
  ){

    taskService.delete(id);
    return ResponseGeneral.ofSuccess(
          messageService.getMessage(SUCCESS, language)
    );
  }

  @GetMapping
  public ResponseGeneral<List<TaskResponse>> list(
        @RequestParam(name = "keyword") String keyword,
        @RequestHeader(name = LANGUAGE, defaultValue = DEFAULT_LANGUAGE) String language
  ){

    return ResponseGeneral.ofSuccess(
          messageService.getMessage(SUCCESS, language),
          taskService.list(keyword)
    );
  }

  @GetMapping("/{id}")
  public ResponseGeneral<TaskResponse> detail(
        @PathVariable String id,
        @RequestHeader(name = LANGUAGE, defaultValue = DEFAULT_LANGUAGE) String language
  ){

    return ResponseGeneral.ofSuccess(
          messageService.getMessage(SUCCESS, language),
          taskFacadeService.detail(id)
    );
  }
}
