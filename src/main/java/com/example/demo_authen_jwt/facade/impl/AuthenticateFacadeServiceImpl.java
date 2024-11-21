package com.example.demo_authen_jwt.facade.impl;

import com.example.demo_authen_jwt.configuration.PropertiesConfiguration;
import com.example.demo_authen_jwt.dto.request.authenticate.CreateTokenRequest;
import com.example.demo_authen_jwt.dto.request.authenticate.LoginRequest;
import com.example.demo_authen_jwt.dto.request.authenticate.RefreshTokenRequest;
import com.example.demo_authen_jwt.dto.response.authenticate.LoginResponse;
import com.example.demo_authen_jwt.entity.User;
import com.example.demo_authen_jwt.enums.TokenType;
import com.example.demo_authen_jwt.exception.authenticate.PasswordIncorrectException;
import com.example.demo_authen_jwt.exception.authenticate.TokenInvalidException;
import com.example.demo_authen_jwt.facade.AuthenticateFacadeService;
import com.example.demo_authen_jwt.service.UserService;
import com.example.demo_authen_jwt.service.authenticate.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static com.example.demo_authen_jwt.utils.PasswordEncoderUtils.getPasswordEncoder;

@Service
@RequiredArgsConstructor
public class AuthenticateFacadeServiceImpl implements AuthenticateFacadeService {
  private final UserService userService;
  private final TokenService tokenService;
  private final PropertiesConfiguration propertiesConfiguration;

  @Override
  public LoginResponse login(LoginRequest request) {

    User user = userService.findByUserName(request.email());
    this.equalPassword(request.password(), user.getPassword());

    var tokenData = this.buildTokenData(user);

    final var accessToken = createToken(user.getId(), tokenData, TokenType.ACCESS_TOKEN);
    final var refreshToken = createToken(user.getId(), tokenData, TokenType.REFRESH_TOKEN);


    return new LoginResponse(
          user.getId(),
          accessToken,
          refreshToken,
          propertiesConfiguration.getAccessTokenTtl(),
          propertiesConfiguration.getRefreshTokenTtl()
    );
  }

  @Override
  public LoginResponse refreshToken(RefreshTokenRequest request) {
    final var refreshTokenRequest = request.refreshToken();

    if (Objects.isNull(refreshTokenRequest) || refreshTokenRequest.isBlank()) {

      throw new TokenInvalidException();
    }

    final var userId = tokenService.getTokenSubject(refreshTokenRequest, TokenType.REFRESH_TOKEN);
    final var user = userService.findById(userId);


    final var tokenData = buildTokenData(user);

    final var accessToken = createToken(user.getId(), tokenData, TokenType.ACCESS_TOKEN);
    final var refreshToken = createToken(user.getId(), tokenData, TokenType.REFRESH_TOKEN);

    return new LoginResponse(
          user.getId(),
          accessToken,
          refreshToken,
          propertiesConfiguration.getAccessTokenTtl(),
          propertiesConfiguration.getRefreshTokenTtl());
  }


  private void equalPassword(String passwordRaw, String passwordEncrypted) {
    if (!getPasswordEncoder().matches(passwordRaw, passwordEncrypted)) {
      throw new PasswordIncorrectException();
    }
  }

  private Map<String, String> buildTokenData(User user) {
    final var tokenData = new HashMap<String, String>();
    tokenData.put("email", user.getEmail());
    tokenData.put("name", user.getName());
    tokenData.put("user_id", String.valueOf(user.getId()));

    return tokenData;
  }

  private String createToken(String subject, Map<String, String> data, TokenType tokenType) {


    Long expired = null;
    if (Objects.equals(tokenType, TokenType.ACCESS_TOKEN)) {
      expired = propertiesConfiguration.getAccessTokenTtl();
    } else if (Objects.equals(tokenType, TokenType.REFRESH_TOKEN)) {
      expired = propertiesConfiguration.getRefreshTokenTtl();
    }

    final var createTokenRequest = new CreateTokenRequest(subject, tokenType, expired, data);

    return tokenService.createToken(createTokenRequest);
  }
}

