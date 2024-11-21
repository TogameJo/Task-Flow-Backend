package com.example.demo_authen_jwt.dto.response;

import com.example.demo_authen_jwt.enums.Priority;
import com.example.demo_authen_jwt.enums.StatusTask;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TaskResponse {
  private String id;
  private String title;
  private String description;
  private String date;
  private Priority priority;
  private StatusTask status;
  private UserResponse user;
  private List<CommentResponse> comments;

  public TaskResponse(String id,
                      String title,
                      String description,
                      String date,
                      Priority priority,
                      StatusTask status,
                      String userId, String email, String name
  ) {
    this.id = id;
    this.title = title;
    this.description = description;
    this.date = date;
    this.priority = priority;
    this.status = status;
    this.user = new UserResponse(userId, email, name);
  }
}
