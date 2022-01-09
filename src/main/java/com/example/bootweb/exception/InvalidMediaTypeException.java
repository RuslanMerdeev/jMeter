package com.example.bootweb.exception;

import com.example.bootweb.support.error.Errors;

public class InvalidMediaTypeException extends ApplicationException {
  public static final String ERROR = Errors.ERROR_INVALID_MEDIA_TYPE;

  public InvalidMediaTypeException() {
    super(ERROR);
  }

  public InvalidMediaTypeException(String message) {
    super(message, ERROR);
  }

  public InvalidMediaTypeException(String message, Throwable cause) {
    super(message, cause, ERROR);
  }

  public InvalidMediaTypeException(Throwable cause) {
    super(cause, ERROR);
  }

  public InvalidMediaTypeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace, ERROR);
  }
}
