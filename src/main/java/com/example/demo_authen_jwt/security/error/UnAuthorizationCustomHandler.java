package com.example.demo_authen_jwt.security.error;


import com.example.demo_authen_jwt.dto.response.ResponseGeneral;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static com.example.demo_authen_jwt.utils.MapperUtils.getMapper;


@Component
@Slf4j
public class UnAuthorizationCustomHandler implements AccessDeniedHandler {

  @Override
  public void handle(
        HttpServletRequest request,
        HttpServletResponse response,
        AccessDeniedException accessDeniedException
  ) throws IOException, ServletException {
    log.error("=== Start handle access denied.");
    final var generalResponse = ResponseGeneral.of(HttpStatus.FORBIDDEN.value(), "Forbidden.", null);
    response.setStatus(HttpStatus.FORBIDDEN.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    getMapper().writeValue(response.getWriter(), generalResponse);
  }
}
