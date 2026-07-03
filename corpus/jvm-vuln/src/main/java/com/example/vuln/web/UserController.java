package com.example.vuln.web;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * corpus: jvm-vuln — public user search. DO NOT DEPLOY.
 * Planted: A03:2021 SQL Injection via string-concatenated JDBC.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final DataSource dataSource;

    public UserController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    // A03:2021 — SQL Injection: tainted `q` concatenated straight into raw SQL,
    // executed on a public (unauthenticated) route.
    @GetMapping("/search")
    public List<String> search(@RequestParam("q") String q) throws Exception {
        List<String> names = new ArrayList<>();
        String sql = "SELECT name FROM app_user WHERE name = '" + q + "'";
        try (Connection conn = dataSource.getConnection();
                Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                names.add(rs.getString(1));
            }
        }
        return names;
    }
}
