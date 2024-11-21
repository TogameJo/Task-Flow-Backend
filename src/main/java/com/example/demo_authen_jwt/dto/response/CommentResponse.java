package com.example.demo_authen_jwt.dto.response;

import com.example.demo_authen_jwt.utils.DateUtils;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class CommentResponse {
  private String id;
  private String content;
  private String createdAt;
  private UserResponse author;


  public CommentResponse(String id, String content,  Long createdAt,
                         String userId, String email, String name
  ) {
    this.id = id;
    this.content = content;
    this.createdAt = DateUtils.convertToMillisSecond(createdAt);
    this.author = new UserResponse(userId, email, name);

  }
}
