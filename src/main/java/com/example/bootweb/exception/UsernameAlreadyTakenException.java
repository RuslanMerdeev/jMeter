package com.example.bootweb.exception;

import com.example.bootweb.support.error.Errors;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class UsernameAlreadyTakenException extends ApplicationException {
  public static final String ERROR = Errors.ERROR_USERNAME_ALREADY_TAKEN;

  public UsernameAlreadyTakenException() {
    super(ERROR);
  }

  public UsernameAlreadyTakenException(String message) {
    super(message, ERROR);
  }

  public UsernameAlreadyTakenException(String message, Throwable cause) {
    super(message, cause, ERROR);
  }

  public UsernameAlreadyTakenException(Throwable cause) {
    super(cause, ERROR);
  }

  public UsernameAlreadyTakenException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace, ERROR);
  }
}
