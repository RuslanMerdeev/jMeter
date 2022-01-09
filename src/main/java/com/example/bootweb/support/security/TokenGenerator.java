package com.example.bootweb.support.security;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.stereotype.Component;

@Component
public class TokenGenerator {
  private final String prefix = "tk_";
  private final StringKeyGenerator keyGenerator = new Base64StringKeyGenerator(64);

  public String generate() {
    // ...
    return prefix + keyGenerator.generateKey();
  }
}