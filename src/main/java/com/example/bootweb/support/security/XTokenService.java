package com.example.bootweb.support.security;

import org.springframework.security.core.userdetails.UserDetails;

public interface XTokenService {
  UserDetails findByToken(String token) throws TokenNotFoundException;
}
