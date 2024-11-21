package com.example.demo_authen_jwt.exception.comment;

import com.example.demo_authen_jwt.exception.base.NotFoundException;

public class CommentNotFoundException extends NotFoundException {
  public CommentNotFoundException() {
    super("com.example.demo_authen_jwt.exception.comment.CommentNotFoundException");
  }
}
