package com.example.bootweb.rest;

import com.example.bootweb.dto.RegistrationRequestDto;
import com.example.bootweb.dto.RegistrationResponseDto;
import com.example.bootweb.service.UserService;
import com.example.bootweb.support.security.ApplicationUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@RestController
@RequestMapping("/api/users")
@Validated
@RequiredArgsConstructor
public class UserController {
  private final UserService service;
  private final HttpServletRequest request; // scope=Request

  @PreAuthorize("isAnonymous()")
  @PostMapping("/register")
  public RegistrationResponseDto register(@RequestBody @Valid RegistrationRequestDto requestDto) {
    return service.register(requestDto);
  }

  @PreAuthorize("isAuthenticated()")
  @GetMapping("/me")
  // FIXME: just for demo
  public ApplicationUserDetails register(@AuthenticationPrincipal ApplicationUserDetails details) {
    return details;
  }
}
