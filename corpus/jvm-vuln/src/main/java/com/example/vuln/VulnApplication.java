package com.example.vuln;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** corpus: jvm-vuln — intentionally vulnerable Spring Boot entrypoint. DO NOT DEPLOY. */
@SpringBootApplication
public class VulnApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnApplication.class, args);
    }
}
