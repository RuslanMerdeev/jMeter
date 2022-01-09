package com.example.bootweb.repository;

import com.example.bootweb.entity.TokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<TokenEntity, String> {
  Optional<TokenEntity> findByValue(String value);
}
