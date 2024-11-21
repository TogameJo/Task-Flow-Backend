package com.example.demo_authen_jwt.entity.base;

import jakarta.persistence.MappedSuperclass;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;

@EqualsAndHashCode(callSuper = true)
@Data
@MappedSuperclass
public class AuditEntity extends BaseEntity {
  @CreatedBy
  private String createdBy;

  @CreatedDate
  private Long createdAt;

  @LastModifiedBy
  private String lastUpdatedBy;

  @LastModifiedDate
  private Long lastUpdatedAt;
}
