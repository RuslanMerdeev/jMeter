package com.example.bootweb.service;

import com.example.bootweb.dto.MediaSaveResponseDto;
import com.example.bootweb.exception.InvalidMediaTypeException;
import com.example.bootweb.exception.MediaUploadException;
import org.apache.tika.Tika;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;

@Service
public class MediaService implements InitializingBean {
  private final Path mediaPath;
  private final Tika tika;
  private final Map<String, String> allowedMime = Map.of(
      "image/png", ".png",
      "image/jpeg", ".jpg"
  );

  public MediaService(@Value("${app.media-path:./media}") Path mediaPath, Tika tika) {
    this.mediaPath = mediaPath;
    this.tika = tika;
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    Files.createDirectories(mediaPath);
  }

  public MediaSaveResponseDto save(MultipartFile file) {
    try {
      final var mime = tika.detect(file.getInputStream());
      final var path = UUID.randomUUID() + allowedMime.get(mime);
      if (!allowedMime.containsKey(mime)) {
        throw new InvalidMediaTypeException(mime);
      }
      file.transferTo(mediaPath.resolve(path));

      return new MediaSaveResponseDto(path);
    } catch (IOException e) {
      throw new MediaUploadException(e);
    }
  }
}
