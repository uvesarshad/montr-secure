package com.example.clean.web;

import java.net.InetAddress;
import java.util.Set;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * corpus: jvm-clean — network diagnostics without any OS command execution.
 * The host is checked against an allow-list and resolved via the JDK resolver;
 * no shell, no Runtime.exec, no ProcessBuilder.
 */
@RestController
@RequestMapping("/api/net")
public class NetworkController {

    private static final Set<String> ALLOWED = Set.of("db.internal", "cache.internal");

    @GetMapping("/diag")
    public String diag(@RequestParam("host") String host) throws Exception {
        if (!ALLOWED.contains(host)) {
            return "host not permitted";
        }
        InetAddress address = InetAddress.getByName(host);
        return address.isReachable(1000) ? "reachable" : "unreachable";
    }
}
