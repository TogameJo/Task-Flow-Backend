package com.example.demo_authen_jwt.security;


import com.example.demo_authen_jwt.entity.User;
import com.example.demo_authen_jwt.exception.base.UnauthorizedException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Objects;
import java.util.Optional;

import static javax.lang.model.element.NestingKind.ANONYMOUS;


@Slf4j
public class UserAuthenticated {
  private UserAuthenticated() {}
  public static Optional<User> getCurrentUser() {
    var authenticate = SecurityContextHolder.getContext().getAuthentication();
    log.debug("=== authenticate: {}", authenticate);
    log.debug("=== principal: {}", authenticate.getPrincipal().toString());
    if (Objects.equals(authenticate.getPrincipal(), ANONYMOUS)) {
      log.error("(getCurrentUser) ===== Unauthorized");
      throw new UnauthorizedException();
    }

    return Optional.of(authenticate)
          .map(authentication -> (User) authenticate.getPrincipal());
  }

  public static User getCurrentUserThrowUnAuthorized() {
    Authentication authenticate = SecurityContextHolder.getContext().getAuthentication();
    log.debug("=== authenticate: {}", authenticate);

    if (authenticate == null || !authenticate.isAuthenticated()) {
      throw new UnauthorizedException();
    }

    log.debug("=== principal: {}", authenticate.getPrincipal().toString());

    return Optional.ofNullable(authenticate.getPrincipal())
          .filter(User.class::isInstance)
          .map(User.class::cast)
          .orElseThrow(UnauthorizedException::new);
  }
}
