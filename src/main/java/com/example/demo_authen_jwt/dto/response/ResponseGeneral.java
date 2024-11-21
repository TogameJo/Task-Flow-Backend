package com.example.demo_authen_jwt.dto.response;


import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

import java.time.LocalDate;

@Data
@AllArgsConstructor(staticName = "of")
@NoArgsConstructor
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ResponseGeneral<T> {
  private int status;
  private String message;
  private T data;
  private String timestamp;

  public static <T> ResponseGeneral<T> of(int status, String message, T data) {
    return of(status, message, data, LocalDate.now().toString());
  }

  public static <T> ResponseGeneral<T> ofSuccess(String message, T data) {
    return of(HttpStatus.OK.value(), message, data, LocalDate.now().toString());
  }

  public static <T> ResponseGeneral<T> ofSuccess(String message) {
    return of(HttpStatus.OK.value(), message, null, LocalDate.now().toString());
  }

  public static <T> ResponseGeneral<T> ofCreated(String message, T data) {
    return of(HttpStatus.CREATED.value(), message, data, LocalDate.now().toString());
  }
}
