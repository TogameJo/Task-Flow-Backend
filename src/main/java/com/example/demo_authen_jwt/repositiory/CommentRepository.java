package com.example.demo_authen_jwt.repositiory;

import com.example.demo_authen_jwt.dto.response.CommentResponse;
import com.example.demo_authen_jwt.entity.Comment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CommentRepository extends JpaRepository<Comment, String> {

  @Query("""
        SELECT new com.example.demo_authen_jwt.dto.response.CommentResponse(
         c.id, c.content, c.createdAt, u.id, u.email, u.name
        ) FROM Comment c
        LEFT JOIN User u ON c.createdBy = u.email
        WHERE c.taskId = :taskId
        """)
  List<CommentResponse> getCommentByTaskId(String taskId);
}
