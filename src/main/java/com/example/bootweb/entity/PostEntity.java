package com.example.bootweb.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.Instant;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
public class PostEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private long id;
  @ManyToOne(optional = false)
  private UserEntity author;
  private String content;
  @Column(updatable = false, nullable = false, insertable = false, columnDefinition = "timestamptz DEFAULT current_timestamp")
  private Instant created;
}
