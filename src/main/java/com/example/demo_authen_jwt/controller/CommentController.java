package com.example.demo_authen_jwt.controller;

import com.example.demo_authen_jwt.dto.request.comment.CommentRequest;
import com.example.demo_authen_jwt.dto.response.ResponseGeneral;
import com.example.demo_authen_jwt.facade.CommentFacadeService;
import com.example.demo_authen_jwt.service.MessageService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import static com.example.demo_authen_jwt.constant.AuthConstant.MessageException.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/comments")
public class CommentController {
  private final CommentFacadeService commentFacadeService;
  private final MessageService messageService;

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public ResponseGeneral<Void> create(
        @RequestBody CommentRequest request,
        @RequestHeader(name = LANGUAGE, defaultValue = DEFAULT_LANGUAGE) String language
  ) {

    commentFacadeService.createComment(request);
    return ResponseGeneral.ofSuccess(
          messageService.getMessage(SUCCESS, language)
    );
  }
}
