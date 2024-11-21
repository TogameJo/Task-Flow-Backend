package com.example.demo_authen_jwt.facade;

import com.example.demo_authen_jwt.dto.request.comment.CommentRequest;

public interface CommentFacadeService {
  void createComment(CommentRequest commentRequest);

}
