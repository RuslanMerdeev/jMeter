package com.example.bootweb.rest;

import com.example.bootweb.dto.PostResponseDto;
import com.example.bootweb.service.PostService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import java.util.List;

@Validated
@RestController
@RequestMapping("/api/posts")
@RequiredArgsConstructor // scope=Singleton
public class PostController {
  private final PostService service;

  @GetMapping
  public List<PostResponseDto> getAll(
      @RequestParam(defaultValue = "0") @Min(0) int page,
      @RequestParam(defaultValue = "50") @Min(10) @Max(50) int count,
      Authentication authentication
  ) {
    return service.findAll(page, count);
  }
}
