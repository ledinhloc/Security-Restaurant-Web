package com.restaurant.management.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    private static final String[] ADMIN_ENDPOINTS = {
            "/inventories/**", "/tables", "/employees/**", "/customers",
            "/dashboard", "/shifts", "/suppliers/**", "/dishes",
            "/recipes/**", "/schedules", "/reservations"
    };

    private static final String[] PUBLIC_ENDPOINTS = {
            "/login", "/request-otp", "/register", "/verify-otp",
            "/forgot-password", "/resources/**", "/css/**", "/"
    };


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .requestMatchers(ADMIN_ENDPOINTS).hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/profile", false)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                )
                .userDetailsService(customUserDetailsService)
                .sessionManagement(session -> session
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                );
//                .headers(headers -> headers
//                        .contentSecurityPolicy(csp -> csp
//                                .policyDirectives(
//                                        "default-src 'self'; " +
//                                                "script-src 'self' https://cdn.tailwindcss.com; " +
//                                                "style-src 'self' ; " +
//                                                "img-src 'self' data:; " +
//                                                "font-src 'self'; " +
//                                                "connect-src 'self'; " +
//                                                "frame-ancestors 'none'; " +
//                                                "form-action 'self'; " +
//                                                "base-uri 'self'"
//                                )
//                        )
//                );

//                .headers(headers -> headers
//                        .contentSecurityPolicy(csp -> csp
//                                .policyDirectives("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:")
//                        )
//                );
//            .headers(headers -> headers
//                    .contentSecurityPolicy(csp -> csp
//                            .policyDirectives(
//                                    "default-src 'self'; " +
//                                            "script-src 'self' https://cdn.jsdelivr.net; " +
//                                            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
//                                            "font-src 'self' https://fonts.gstatic.com; " +
//                                            "img-src 'self' data:; " +
//                                            "connect-src 'self' https://api.example.com; " +
//                                            "frame-src 'none'; " +
//                                            "object-src 'none';"
//                            )
//                    )
//            );

        http.csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return customUserDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
