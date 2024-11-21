package com.example.demo_authen_jwt.repositiory;

import com.example.demo_authen_jwt.dto.response.TaskResponse;
import com.example.demo_authen_jwt.entity.Task;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TaskRepository extends JpaRepository<Task, String> {
  boolean existsById(String id);

  @Query("""
        SELECT new com.example.demo_authen_jwt.dto.response.TaskResponse(
         t.id,t.title, t.description, t.date, t.priority, t.status, u.id, u.email, u.name
        ) FROM Task t
        LEFT JOIN User u ON t.userId = u.id
        WHERE t.id = :id
        """)
 Optional<TaskResponse> get(String id);


  @Query("""
        SELECT new com.example.demo_authen_jwt.dto.response.TaskResponse(
         t.id,t.title, t.description, t.date, t.priority, t.status, u.id, u.email, u.name
        ) FROM Task t
        LEFT JOIN User u ON t.userId = u.id
        WHERE :keyword = '' OR lower(t.title) LIKE lower(concat('%', :keyword, '%'))
        AND :keyword = '' OR lower(t.description) LIKE lower(concat('%', :keyword, '%'))
        AND :keyword = '' OR lower(u.name) LIKE lower(concat('%', :keyword, '%'))
        """)
  List<TaskResponse> list(String keyword);
}
