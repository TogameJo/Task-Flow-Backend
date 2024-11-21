package com.example.demo_authen_jwt.entity;

import com.example.demo_authen_jwt.entity.base.AuditEntity;
import com.example.demo_authen_jwt.entity.base.BaseEntity;
import com.example.demo_authen_jwt.enums.Priority;
import com.example.demo_authen_jwt.enums.StatusTask;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "tasks")
@AllArgsConstructor
public class Task extends AuditEntity {
  private String title;
  private String description;
  private String date;
  private Priority priority;
  private StatusTask status;
  private String userId;
}
