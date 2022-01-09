package com.example.bootweb.service;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class SecurityService {
  public boolean hasPermission(Authentication authentication, Object object) {
    return false;
  }
}
