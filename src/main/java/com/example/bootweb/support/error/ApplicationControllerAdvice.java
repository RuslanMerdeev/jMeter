package com.example.bootweb.support.error;

import com.example.bootweb.exception.ApplicationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApplicationControllerAdvice {
  @ExceptionHandler
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ErrorResponseDto error(Throwable e) {
    // TODO: fix
    return new ErrorResponseDto(e.getMessage());
  }

  @ExceptionHandler
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ErrorResponseDto error(MethodArgumentNotValidException e) {
    // TODO: fix
    return new ErrorResponseDto(e.getMessage());
  }

  @ExceptionHandler
  public ResponseEntity<ErrorResponseDto> error(ApplicationException e) {
    HttpStatus statusCode = HttpStatus.BAD_REQUEST;
    if (e.getClass().isAnnotationPresent(ResponseStatus.class)) {
      statusCode = e.getClass().getAnnotation(ResponseStatus.class).value();
    }
    return ResponseEntity.status(statusCode)
        .body(new ErrorResponseDto(e.getCode()));
  }
}
