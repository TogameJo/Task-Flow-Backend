package com.example.demo_authen_jwt.service.impl;

import com.example.demo_authen_jwt.dto.request.comment.CommentRequest;
import com.example.demo_authen_jwt.dto.response.CommentResponse;
import com.example.demo_authen_jwt.entity.Comment;
import com.example.demo_authen_jwt.exception.comment.CommentNotFoundException;
import com.example.demo_authen_jwt.repositiory.CommentRepository;
import com.example.demo_authen_jwt.service.CommentService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
@RequiredArgsConstructor
public class CommentServiceImpl implements CommentService {
  private final CommentRepository repository;

  @Override
  public void create(CommentRequest request) {
    Comment comment = new Comment(
          request.getContent(),
          request.getTaskId()
    );
    repository.save(comment);
  }


  @Override
  public List<CommentResponse> findByTaskId(String taskId) {
    return repository.getCommentByTaskId(taskId);
  }

  private Comment find(String id) {
    return repository.findById(id).orElseThrow(CommentNotFoundException::new);
  }
}
