package com.example.bootweb.dto;

import com.example.bootweb.support.validation.NotAllowedNames;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class RegistrationRequestDto {
  @NotNull
  @NotBlank
  @Pattern(regexp = "^[-0-9a-zA-z]+")
  @Size(min = 2, max = 50)
  @NotAllowedNames({"admin", "root"})
  private String username;
  @NotNull
  @Size(min = 8, max = 60)
  private String password;
  private String avatar;
}
