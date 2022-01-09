package com.example.bootweb.mapper;

import com.example.bootweb.dto.PostResponseDto;
import com.example.bootweb.entity.PostEntity;
import com.example.bootweb.entity.UserEntity;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper
public interface PostMapper {
  PostResponseDto fromEntity(PostEntity entity);

  List<PostResponseDto> fromEntities(List<PostEntity> entities);

  PostResponseDto.AuthorResponseDto fromEntity(UserEntity entity);
}
