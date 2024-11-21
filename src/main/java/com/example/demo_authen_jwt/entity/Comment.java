package com.example.demo_authen_jwt.entity;

import com.example.demo_authen_jwt.entity.base.AuditEntity;
import com.example.demo_authen_jwt.entity.base.BaseEntity;
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
@Table(name = "comments")
@AllArgsConstructor
public class Comment extends AuditEntity {
  private String content;
  private String taskId;
}
