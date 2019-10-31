package com.b3c2bab2.springsecuritydemo.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author b3c2bab2
 * created on 2019/10/30
 */
@EnableWebSecurity
public class AccessConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.rememberMe().and()
//                .httpBasic().and()
//                .authorizeRequests()
//                .anyRequest().access("hasRole('ROLE_USER') or request.method == 'GET'");
        http.authorizeRequests()
                .antMatchers("/index").permitAll()
                .antMatchers("/info").hasRole("ADMIN").and()
                .formLogin()
                .loginPage("/login")
                .failureUrl("/login-error");
    }
}
