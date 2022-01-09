package com.example.bootweb.support.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
@RequiredArgsConstructor
public class XTokenAuthenticationProvider implements AuthenticationProvider {
  private final XTokenService service;
  private final UserDetailsChecker userDetailsChecker;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    Assert.isInstanceOf(XAuthenticationToken.class, authentication, "Only XAuthToken is supported");

    final var token = (XAuthenticationToken) authentication;
    final var principal = (String) token.getPrincipal();
    final var userDetails = service.findByToken(principal);
    userDetailsChecker.check(userDetails);

    return new XAuthenticationToken(
        userDetails,
        userDetails.getPassword(),
        userDetails.getAuthorities()
    );
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return XAuthenticationToken.class.equals(authentication);
  }
}
