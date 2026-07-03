package com.example.vuln.web;

import jakarta.servlet.http.HttpServletRequest;
import java.io.ObjectInputStream;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * corpus: jvm-vuln — public state import. DO NOT DEPLOY.
 * Planted: A08:2021 Insecure Deserialization of untrusted request bytes.
 */
@RestController
@RequestMapping("/api/import")
public class ImportController {

    // A08:2021 — Insecure Deserialization: raw request bytes are fed into a
    // native ObjectInputStream and materialised with readObject(), enabling
    // gadget-chain RCE. Public, unauthenticated route.
    @PostMapping
    public String load(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        Object payload = in.readObject();
        return String.valueOf(payload);
    }
}
