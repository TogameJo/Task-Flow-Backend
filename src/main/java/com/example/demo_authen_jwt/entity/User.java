package com.example.demo_authen_jwt.entity;

import com.example.demo_authen_jwt.entity.base.AuditEntity;
import io.micrometer.common.util.StringUtils;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "users")
public class User extends AuditEntity {
  private String email;
  private String password;
  private String name;

  public User(String email, String password, String name) {
    this.password = password;
    this.email = email;
    this.name = name;
  }



}
