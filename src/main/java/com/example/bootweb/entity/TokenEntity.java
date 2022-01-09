package com.example.bootweb.entity;

import lombok.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import java.time.Instant;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
@Builder
public class TokenEntity {
  @Id
  private String value;
  @ManyToOne(optional = false)
  private UserEntity user;
  @Column(updatable = false, nullable = false, insertable = false, columnDefinition = "timestamptz DEFAULT current_timestamp")
  private Instant created;

  public TokenEntity(String value, UserEntity user) {
    this.value = value;
    this.user = user;
  }
}
