package com.restaurant.management.service;

import com.cloudinary.Cloudinary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@Service
public class StorageService {
    @Autowired
    private Cloudinary cloudinary;

    public String uploadImage(MultipartFile file) throws IOException {
        return uploadImage(file.getBytes());
    }

    public String uploadImage(byte[] imageBytes) throws IOException {
        Map uploadResult = cloudinary.uploader().upload(imageBytes, Map.of());
        if (uploadResult.containsKey("url")) {
            return uploadResult.get("url").toString();
        } else {
            throw new RuntimeException("Upload failed: URL not found in the result");
        }

    }
}
