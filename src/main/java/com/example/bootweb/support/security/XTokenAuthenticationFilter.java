package com.example.bootweb.support.security;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class XTokenAuthenticationFilter extends OncePerRequestFilter {
  private final AuthenticationManager manager;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    // old school: custom headers X-*
    // now in HTTP: X-* deprecated
    final String token = request.getHeader("X-Token");
    if (token == null) {
      filterChain.doFilter(request, response);
      return;
    }

    if (!authenticationIsRequired()) {
      filterChain.doFilter(request, response);
      return;
    }

    try {
      final Authentication authResult = manager.authenticate(new XAuthenticationToken(token, ""));
      if (logger.isDebugEnabled()) {
        logger.debug("Authentication success: " + authResult);
      }
      SecurityContextHolder.getContext().setAuthentication(authResult);
    } catch (AuthenticationException e) {
      e.printStackTrace();
      SecurityContextHolder.clearContext();

      /*
      AuthenticationEntryPoint

      HTTP/1.1 401 Unauthorized
      WWW-Authenticate: X-Token realm="..."
       */
      response.addHeader("WWW-Authenticate", "X-Token");
      response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
      return;
    }

    filterChain.doFilter(request, response);
  }

  private boolean authenticationIsRequired() {
    final var existingAuth = SecurityContextHolder.getContext().getAuthentication();

    if (existingAuth == null || !existingAuth.isAuthenticated()) {
      return true;
    }

    return existingAuth instanceof AnonymousAuthenticationToken;
  }
}
