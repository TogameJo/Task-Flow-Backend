package com.example.demo_authen_jwt.dto.request.task;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class TaskRequest {
  private String title;
  private String description;
  private int priority;
  private int status;
  private String date;
  private String userId;
}
