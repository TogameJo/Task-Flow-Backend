package com.example.demo_authen_jwt.security.error;


import com.example.demo_authen_jwt.dto.response.ResponseGeneral;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static com.example.demo_authen_jwt.utils.MapperUtils.getMapper;


@Component
@Slf4j
public class UnAuthenticationCustomHandler implements AuthenticationEntryPoint {
  @Override
  public void commence(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException authException
  ) throws IOException, ServletException {
    log.error("=== Start commence handle authentication error");
    var generalResponse = ResponseGeneral.of(HttpStatus.UNAUTHORIZED.value(), "Unauthorized.",null);

    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    getMapper().writeValue(response.getWriter(), generalResponse);
  }
}
