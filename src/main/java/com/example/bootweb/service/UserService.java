package com.example.bootweb.service;

import com.example.bootweb.dto.RegistrationRequestDto;
import com.example.bootweb.dto.RegistrationResponseDto;
import com.example.bootweb.entity.TokenEntity;
import com.example.bootweb.mapper.UserMapper;
import com.example.bootweb.repository.TokenRepository;
import com.example.bootweb.repository.UserRepository;
import com.example.bootweb.support.security.Roles;
import com.example.bootweb.support.security.TokenGenerator;
import com.example.bootweb.support.security.TokenNotFoundException;
import com.example.bootweb.support.security.XTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService implements UserDetailsService, XTokenService {
  private final UserRepository userRepository;
  private final TokenRepository tokenRepository;
  private final UserMapper mapper;
  private final PasswordEncoder passwordEncoder;
  private final TokenGenerator tokenGenerator;

  public RegistrationResponseDto register(RegistrationRequestDto requestDto) {
    final var userEntity = mapper.fromRegistrationRequestDto(requestDto, List.of(Roles.ROLE_USER));
    // TODO: check if username is available

    userEntity.setPassword(passwordEncoder.encode(userEntity.getPassword()));
    final var user = userRepository.save(userEntity);
    final var token = tokenRepository.save(new TokenEntity(tokenGenerator.generate(), user));
    return mapper.registrationFromEntity(userEntity, token);
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return userRepository.findByUsername(username)
        .map(mapper::detailsFromEntity)
        .orElseThrow(() -> new UsernameNotFoundException(username))
        ;
  }

  @Override
  public UserDetails findByToken(String token) {
    return tokenRepository.findByValue(token)
        .map(TokenEntity::getUser)
        .map(mapper::detailsFromEntity)
        .orElseThrow(() -> new TokenNotFoundException("token not found"))
        ;
  }
}
