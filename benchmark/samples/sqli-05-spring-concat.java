package com.owasp.webgoat.lessons;

import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;
import java.util.Map;

public class SqlInjectionLesson {
    private JdbcTemplate jdbcTemplate;

    public List<Map<String, Object>> searchUsers(String accountName) {
        return jdbcTemplate.queryForList("SELECT * FROM user_data WHERE user_name = '" + accountName + "'");
    }
}

