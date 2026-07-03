package com.example.clean.web;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * corpus: jvm-clean — state import via a typed DTO bound by Jackson.
 * No native ObjectInputStream / readObject: the body is parsed into a strongly
 * typed record, so there is no deserialization gadget surface.
 */
@RestController
@RequestMapping("/api/import")
public class ImportController {

    @PostMapping
    public String load(@RequestBody OrderDto dto) {
        return "imported " + dto.name();
    }

    public record OrderDto(String name, long total) {
    }
}
