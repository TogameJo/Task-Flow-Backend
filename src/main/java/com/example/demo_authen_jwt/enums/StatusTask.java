package com.example.demo_authen_jwt.enums;

import lombok.Getter;

@Getter
public enum StatusTask {
  PENDING(0),
  IN_PROGRESS(1);
  // Getter method to retrieve the status code
  private final int statusCode;

  // Constructor
  StatusTask(int statusCode) {
    this.statusCode = statusCode;
  }

  // Method to get StatusTask by status code
  public static StatusTask fromStatusCode(int statusCode) {
    for (StatusTask status : StatusTask.values()) {
      if (status.statusCode == statusCode) {
        return status;
      }
    }
    throw new IllegalArgumentException("Invalid status code: " + statusCode);
  }

  @Override
  public String toString() {
    return this.name() + "(" + this.statusCode + ")";
  }
}
