package com.example.vuln.web;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * corpus: jvm-vuln — public network diagnostics. DO NOT DEPLOY.
 * Planted: A03:2021 OS Command Injection via Runtime.exec.
 */
@RestController
@RequestMapping("/api/net")
public class NetworkController {

    // A03:2021 — OS Command Injection: request input flows into Runtime.exec
    // with shell-style string concatenation, no allow-list, on a public route.
    @GetMapping("/diag")
    public String diag(@RequestParam("host") String host) throws Exception {
        Process proc = Runtime.getRuntime().exec("ping -c 1 " + host);
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        StringBuilder out = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            out.append(line).append('\n');
        }
        return out.toString();
    }
}
