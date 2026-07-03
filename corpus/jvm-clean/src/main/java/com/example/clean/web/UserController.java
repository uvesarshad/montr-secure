package com.example.clean.web;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * corpus: jvm-clean — public user search using a parameterized query.
 * The tainted `q` is bound as a `?` placeholder, so it never reaches raw SQL.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final DataSource dataSource;

    public UserController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/search")
    public List<String> search(@RequestParam("q") String q) throws Exception {
        List<String> names = new ArrayList<>();
        String sql = "SELECT name FROM app_user WHERE name = ?";
        try (Connection conn = dataSource.getConnection();
                PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, q);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    names.add(rs.getString(1));
                }
            }
        }
        return names;
    }
}
