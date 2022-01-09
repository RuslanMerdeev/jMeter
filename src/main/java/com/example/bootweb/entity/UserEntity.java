package com.example.bootweb.entity;

import lombok.*;

import javax.persistence.*;
import java.time.Instant;
import java.util.List;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
@Builder
public class UserEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private long id;
  @Column(unique = true, nullable = false, columnDefinition = "TEXT")
  private String username;
  @Column(nullable = false, columnDefinition = "TEXT")
  private String password;
  @Column(nullable = false, columnDefinition = "TEXT DEFAULT 'noavatar.png'")
  private String avatar;
  @ElementCollection(fetch = FetchType.EAGER)
  private List<String> authorities;
  @Column(nullable = false)
  private boolean disabled = false;
  @Column(updatable = false, nullable = false, insertable = false, columnDefinition = "timestamptz DEFAULT current_timestamp")
  private Instant created;
}
