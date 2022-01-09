package com.example.bootweb.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class PostRequestDto {
  private long id;
  private AuthorResponseDto author;
  private String content;
  private Instant created;

  @NoArgsConstructor
  @AllArgsConstructor
  @Data
  public static class AuthorResponseDto {
    private long id;
    private String name;
//    TODO: add avatar
//    private String avatar;
  }
}
