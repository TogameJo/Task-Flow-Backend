package com.example.demo_authen_jwt.filter;


import com.example.demo_authen_jwt.enums.TokenType;
import com.example.demo_authen_jwt.exception.base.BaseException;
import com.example.demo_authen_jwt.service.UserService;
import com.example.demo_authen_jwt.service.authenticate.TokenService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.antlr.v4.runtime.misc.NotNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;


import static com.example.demo_authen_jwt.constant.AuthConstant.JwtConstant.BEARER_TOKEN_TYPE_START;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private final TokenService tokenService;
  private final UserService userService;


  @Override
  protected void doFilterInternal(
        HttpServletRequest request,
        @NotNull HttpServletResponse response,
        @NotNull FilterChain filterChain
  ) throws ServletException, IOException {
    log.debug("=== Start filter jwt");
    log.debug("Request: {}", request.toString());

    //get header
    final var accessTokenBearer = request.getHeader(AUTHORIZATION);

    if (Objects.isNull(accessTokenBearer) || !accessTokenBearer.startsWith(BEARER_TOKEN_TYPE_START)) {
      log.debug("Token null or invalid, token: {}", accessTokenBearer);
      filterChain.doFilter(request, response);
      return;
    }
    final var accessToken = accessTokenBearer.substring(BEARER_TOKEN_TYPE_START.length());
    log.debug("Access_token: {}", accessToken);

    try {
      final var userId = tokenService.getTokenSubject(accessToken, TokenType.ACCESS_TOKEN);

      log.debug("UserId: {}", userId);

      final var user = userService.detail(userId);
      log.debug("User: {}", user);
      if (Objects.isNull(user)) {
        log.debug("User not found with id: {}", userId);
        filterChain.doFilter(request, response);
        return;
      }


      var authentication = new UsernamePasswordAuthenticationToken(
            user,
            null,
            new ArrayList<>()

      );
      SecurityContextHolder.getContext().setAuthentication(authentication);
      filterChain.doFilter(request, response);

    } catch (ExpiredJwtException e) {
      handleException(e, response, HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
    } catch (SignatureException | MalformedJwtException e) {
      handleException(e, response, HttpServletResponse.SC_UNAUTHORIZED, "Token invalid");
    } catch (BaseException e) {
      handleException(e, response, e.getStatus(), e.getMessage());
    } catch (Exception e) {
      handleException(e, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal server error");
    }
  }




  private void handleException(Exception e, HttpServletResponse response, int status, String message) throws IOException {
    log.error("(doFilterInternal): {}", e.getMessage());
    response.sendError(status, message);
  }
}
