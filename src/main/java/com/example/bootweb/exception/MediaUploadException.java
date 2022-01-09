package com.example.bootweb.exception;

import com.example.bootweb.support.error.Errors;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class MediaUploadException extends ApplicationException {
  public static final String ERROR = Errors.ERROR_CANT_UPLOAD_MEDIA;

  public MediaUploadException() {
    super(ERROR);
  }

  public MediaUploadException(String message) {
    super(message, ERROR);
  }

  public MediaUploadException(String message, Throwable cause) {
    super(message, cause, ERROR);
  }

  public MediaUploadException(Throwable cause) {
    super(cause, ERROR);
  }

  public MediaUploadException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace, ERROR);
  }
}
