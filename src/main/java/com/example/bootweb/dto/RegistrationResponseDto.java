package com.example.bootweb.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class RegistrationResponseDto {
  private long id;
  private String username;
  private String avatar;
  private String token;
}
