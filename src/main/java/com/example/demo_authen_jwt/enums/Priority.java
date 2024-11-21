package com.example.demo_authen_jwt.enums;

import lombok.Getter;

@Getter
public enum Priority {
  LOW(0),
  MEDIUM(1),
  HIGH(2);

  private final int level;

  Priority(int level) {
    this.level = level;
  }

  public static Priority fromLevel(int level) {
    for (Priority priority : Priority.values()) {
      if (priority.level == level) {
        return priority;
      }
    }
    throw new IllegalArgumentException("Invalid level: " + level);
  }

  @Override
  public String toString() {
    return this.name() + "(" + this.level + ")";
  }
}