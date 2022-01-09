package com.example.bootweb.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class ApplicationException extends RuntimeException {
  @Getter
  private final String code;

  public ApplicationException(String code) {
    this.code = code;
  }

  public ApplicationException(String message, String code) {
    super(message);
    this.code = code;
  }

  public ApplicationException(String message, Throwable cause, String code) {
    super(message, cause);
    this.code = code;
  }

  public ApplicationException(Throwable cause, String code) {
    super(cause);
    this.code = code;
  }

  public ApplicationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace, String code) {
    super(message, cause, enableSuppression, writableStackTrace);
    this.code = code;
  }
}
