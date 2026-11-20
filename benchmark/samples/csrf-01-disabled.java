// Sample 9: Spring Security with CSRF explicitly disabled (Vulnerable)
// Source: OWASP WebGoat (SecurityConfig.java)
// License: Apache-2.0

package org.owasp.webgoat;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Vulnerability: explicitly disabling CSRF protection on authenticated app
        http
            .csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated();
    }
}

