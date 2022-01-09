package com.example.bootweb.service;

import com.example.bootweb.dto.PostResponseDto;
import com.example.bootweb.mapper.PostMapper;
import com.example.bootweb.repository.PostRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
public class PostService {
  private final PostRepository repository;
  private final PostMapper mapper;
  private final Sort idAscDesc = Sort.by(Sort.Direction.DESC, "id");

  public List<PostResponseDto> findAll(int page, int count) {
//    final var principal = (ApplicationUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    return mapper.fromEntities(repository.findAll(PageRequest.of(page, count, idAscDesc)).toList());
  }
}
