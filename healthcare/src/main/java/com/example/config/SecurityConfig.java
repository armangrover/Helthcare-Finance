package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.core.annotation.Order;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Arrays;

@Configuration
public class SecurityConfig {
        @Bean
        @Order(1)
        public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
                http
                                .securityMatcher("/api/**")
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                                .csrf(csrf -> csrf.disable())
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers(
                                                                "/api/auth/**",
                                                                "/v3/api-docs/**",
                                                                "/swagger-ui/**")
                                                .permitAll()
                                                .anyRequest().authenticated())
                                .httpBasic();
                return http.build();
        }

        @Bean
        @Order(2)
        public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
                http
                                .cors(withDefaults()) // Enable CORS for web routes
                                .requiresChannel(channel -> channel.anyRequest().requiresSecure()) // Force HTTPS
                                .csrf(csrf -> csrf.disable())
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers(
                                                                "/", "/login", "/register",
                                                                "/css/**", "/js/**", "/images/**",
                                                                "/favicon.ico")
                                                .permitAll()
                                                .anyRequest().authenticated())
                                .formLogin(form -> form
                                                .loginPage("/login")
                                                .defaultSuccessUrl("/dashboard", true)
                                                .failureUrl("/login?error=true"))
                                .logout(logout -> logout
                                                .logoutUrl("/logout")
                                                .logoutSuccessUrl("/login"))
                                .sessionManagement(session -> session
                                                .maximumSessions(1));
                return http.build();
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(Arrays.asList(
                                "http://localhost:3000",
                                "https://helthcare-finance-production.up.railway.app"));
                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                configuration.setAllowedHeaders(Arrays.asList("*"));
                configuration.setAllowCredentials(true);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/api/**", configuration);
                return source;
        }
}