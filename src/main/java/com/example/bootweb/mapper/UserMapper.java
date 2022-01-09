package com.example.bootweb.mapper;

import com.example.bootweb.dto.RegistrationRequestDto;
import com.example.bootweb.dto.RegistrationResponseDto;
import com.example.bootweb.entity.TokenEntity;
import com.example.bootweb.entity.UserEntity;
import com.example.bootweb.support.security.ApplicationUserDetails;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;

@Mapper
public interface UserMapper {
  @Mappings({
      @Mapping(target = "id", constant = "0L"),
      @Mapping(target = "disabled", constant = "false"),
      @Mapping(
          target = "created",
          ignore = true
      )
  })
  UserEntity fromRegistrationRequestDto(
      RegistrationRequestDto dto,
      List<String> authorities
  );

  @Mappings({
      @Mapping(target = "token", source = "token.value")
  })
  RegistrationResponseDto registrationFromEntity(
      UserEntity entity,
      TokenEntity token
  );

  default ApplicationUserDetails detailsFromEntity(
      UserEntity entity
  ) {
    return new ApplicationUserDetails(
        entity.getId(),
        entity.getUsername(),
        entity.getPassword(),
        entity.getAvatar(),
        entity.getAuthorities().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()),
        true,
        true,
        true,
        true
    );
  }
}
