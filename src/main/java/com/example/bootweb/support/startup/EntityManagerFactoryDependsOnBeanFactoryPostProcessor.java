package com.example.bootweb.support.startup;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.jdbc.support.DatabaseStartupValidator;
import org.springframework.stereotype.Component;

import javax.persistence.EntityManagerFactory;

@Component
public class EntityManagerFactoryDependsOnBeanFactoryPostProcessor implements BeanFactoryPostProcessor {
  @Override
  public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
    final var startups = beanFactory.getBeanNamesForType(DatabaseStartupValidator.class);
    if (startups.length == 0) {
      return;
    }

    for (final String name : beanFactory.getBeanNamesForType(EntityManagerFactory.class)) {
      beanFactory.getBeanDefinition(name).setDependsOn(startups);
    }
  }
}
