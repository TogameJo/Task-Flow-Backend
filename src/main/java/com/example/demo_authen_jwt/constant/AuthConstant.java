package com.example.demo_authen_jwt.constant;

public class AuthConstant {

  public static class MessageException {
    private MessageException() {
    }

    public static final String DEFAULT_CODE_BAD_REQUEST = "com.example.demo_authen_jwt.exception.base.BadRequestException";
    public static final String DEFAULT_CODE_CONFLICT = "com.example.demo_authen_jwt.exception.base.ConflictException";
    public static final String DEFAULT_CODE_NOTFOUND = "com.example.demo_authen_jwt.exception.base.NotFoundException";
    public static final String DEFAULT_CODE_SERVER_ERROR = "com.example.demo_authen_jwt.exception.base.InternalServerError";
    public static final String NOT_FOUND_MESSAGE = "Not found";
    public static final String BAD_REQUEST_MESSAGE = "Bad request";
    public static final String CONFLICT_MESSAGE = "Conflict occurred";
    public static final String BLANK_MESSAGE = "";
    public static final String SUCCESS = "success";
    public static final String LANGUAGE = "Accept-Language";
    public static final String DEFAULT_LANGUAGE = "vi";
    public static final String SYSTEM = "system";
    public static final String ANONYMOUS = "anonymous";

    public static String[] MATCHER_USER_API = {"/api/v1/auth/**", "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**"
          , "/actuator/", "/api/v1/reports/**"};
  }

  public static class JwtConstant {
    private JwtConstant() {
    }

    public static final String TOKEN_TYPE = "Bearer";

    public static final String BEARER_TOKEN_TYPE_START = "Bearer ";

  }
}
