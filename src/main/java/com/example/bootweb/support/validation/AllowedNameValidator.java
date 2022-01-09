package com.example.bootweb.support.validation;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Set;

public class AllowedNameValidator implements ConstraintValidator<NotAllowedNames, String> {
  private Set<String> names;

  @Override
  public void initialize(NotAllowedNames constraintAnnotation) {
    names = Set.of(constraintAnnotation.value());
  }

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {
    return !names.contains(value);
  }
}
