package com.example.bootweb.rest;

import com.example.bootweb.dto.MediaSaveResponseDto;
import com.example.bootweb.service.MediaService;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Validated
@RestController
@RequestMapping("/api/media")
@RequiredArgsConstructor
public class MediaController {
  private final MediaService service;

  @PostMapping
  public MediaSaveResponseDto save(@RequestPart MultipartFile file) {
    return service.save(file);
  }
}
