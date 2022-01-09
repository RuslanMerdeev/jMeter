package com.example.bootweb.support.startup;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.support.DatabaseStartupValidator;

import javax.sql.DataSource;

@Configuration
public class StartupConfiguration {
  @Bean
  public DatabaseStartupValidator databaseStartupValidator(DataSource dataSource) {
    final var databaseStartupValidator = new DatabaseStartupValidator();
    databaseStartupValidator.setDataSource(dataSource);
    return databaseStartupValidator;
  }
}
