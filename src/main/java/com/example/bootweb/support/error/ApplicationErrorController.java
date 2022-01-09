package com.example.bootweb.support.error;

import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.WebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("${server.error.path:${error.path:/error}}")
public class ApplicationErrorController extends AbstractErrorController {
  private final ErrorAttributes errorAttributes;

  public ApplicationErrorController(ErrorAttributes errorAttributes) {
    super(errorAttributes);
    this.errorAttributes = errorAttributes;
  }

  @RequestMapping
  public ResponseEntity<ErrorResponseDto> error(HttpServletRequest request, WebRequest webRequest, HttpServletResponse response) {
    final var httpStatus = HttpStatus.valueOf(response.getStatus());
    final var errors = errorAttributes.getErrorAttributes(webRequest, ErrorAttributeOptions.defaults());
    // если будет exception (например, unsupported media type, то можем вытащить отсюда), может быть и null (для 404)
    final var error = errorAttributes.getError(webRequest);

    return ResponseEntity.status(httpStatus).body(
        new ErrorResponseDto("...")
    );
  }
}
