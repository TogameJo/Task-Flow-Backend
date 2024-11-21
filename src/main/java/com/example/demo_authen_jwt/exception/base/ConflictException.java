package com.example.demo_authen_jwt.exception.base;


import java.util.HashMap;
import java.util.Map;


import static com.example.demo_authen_jwt.constant.AuthConstant.MessageException.*;
import static com.example.demo_authen_jwt.exception.base.StatusConstants.CONFLICT;

public class ConflictException extends BaseException {

  public ConflictException(String id, String objectName) {
    super(DEFAULT_CODE_CONFLICT, CONFLICT_MESSAGE, CONFLICT, createParams(id, objectName));
  }

  public ConflictException() {
    super(DEFAULT_CODE_CONFLICT, CONFLICT_MESSAGE, CONFLICT, null);
  }

  public ConflictException(String code) {
    super(code, BLANK_MESSAGE, CONFLICT, null);
  }

  private static Map<String, String> createParams(String id, String objectName) {
    Map<String, String> params = new HashMap<>();
    params.put("id", id);
    params.put("objectName", objectName);
    return params;
  }
}
