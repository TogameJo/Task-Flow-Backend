package com.example.demo_authen_jwt.configuration.auditor;



import com.example.demo_authen_jwt.dto.response.UserResponse;
import com.example.demo_authen_jwt.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Objects;
import java.util.Optional;


import static com.example.demo_authen_jwt.constant.AuthConstant.MessageException.ANONYMOUS;
import static com.example.demo_authen_jwt.constant.AuthConstant.MessageException.SYSTEM;

@Slf4j
public class AuditorAwareImpl implements AuditorAware<String> {

  @Override
  public Optional<String> getCurrentAuditor() {


    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    log.info("Authentication: " + authentication);

    if (Objects.nonNull(authentication) && !this.isAnonymous() && (Objects.nonNull(authentication.getPrincipal()))) {
      try {
        UserResponse user = (UserResponse) authentication.getPrincipal();
        return Optional.of(user.email());
      }catch (Exception e){
        log.error(e.getMessage());
        //throw new RuntimeException(e);
      }



    }
    return Optional.of(SYSTEM);
  }


  private boolean isAnonymous() {
    return SecurityContextHolder.getContext().getAuthentication().getName().equals(ANONYMOUS);
  }
}
