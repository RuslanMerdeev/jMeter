package com.example.bootweb;

import lombok.extern.apachecommons.CommonsLog;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@CommonsLog
public class BootWebApplication {

  public static void main(String[] args) {
    SpringApplication.run(BootWebApplication.class, args);
  }
}
