package com.example.demo_authen_jwt.security;

import com.example.demo_authen_jwt.filter.JwtAuthenticationFilter;
import com.example.demo_authen_jwt.security.error.UnAuthenticationCustomHandler;
import com.example.demo_authen_jwt.security.error.UnAuthorizationCustomHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import static com.example.demo_authen_jwt.constant.AuthConstant.MessageException.MATCHER_USER_API;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

  // Khai báo các bean và handler cần thiết
  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final UnAuthenticationCustomHandler unAuthenticationCustomHandler;
  private final UnAuthorizationCustomHandler unAuthorizationCustomHandler;

  /**
   * Cấu hình bảo mật cho các API.
   *
   * @param httpSecurity Cấu hình bảo mật của HTTP
   * @return SecurityFilterChain
   * @throws Exception nếu có lỗi xảy ra khi cấu hình
   */
  @Bean
  public SecurityFilterChain securityFilterChainUsersAPILocal(HttpSecurity httpSecurity) throws Exception {
    // Cấu hình chung cho bảo mật
    sharedSecurityConfiguration(httpSecurity);

    // Cấu hình chi tiết quyền truy cập và bộ lọc
    httpSecurity
            .authorizeHttpRequests(auth -> {
              // Cho phép truy cập không cần xác thực vào các endpoint nhất định
              auth.requestMatchers(MATCHER_USER_API).permitAll();
              // Các yêu cầu còn lại cần phải xác thực
              auth.anyRequest().authenticated();
            })
            // Thêm bộ lọc JWT vào chuỗi bảo mật trước bộ lọc UsernamePasswordAuthenticationFilter
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            // Cấu hình xử lý các lỗi xác thực và quyền truy cập
            .exceptionHandling(exception -> exception
                    .authenticationEntryPoint(unAuthenticationCustomHandler) // Không xác thực
                    .accessDeniedHandler(unAuthorizationCustomHandler)); // Không có quyền truy cập

    return httpSecurity.build();
  }

  /**
   * Cấu hình chung cho bảo mật HTTP, bao gồm CORS, CSRF, và Session Management.
   *
   * @param httpSecurity Cấu hình bảo mật của HTTP
   * @throws Exception nếu có lỗi trong quá trình cấu hình
   */
  private void sharedSecurityConfiguration(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
            .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Cấu hình CORS
            .csrf(AbstractHttpConfigurer::disable) // Tắt CSRF vì đây là API bảo mật
            .sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // Cấu hình không sử dụng session
  }

  /**
   * Cấu hình CORS (Cross-Origin Resource Sharing) cho phép các yêu cầu từ các nguồn khác nhau.
   *
   * @return CorsConfigurationSource Cấu hình CORS
   */
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.addAllowedHeader("*"); // Cho phép tất cả các header
    configuration.addAllowedOrigin("*"); // Cho phép tất cả các nguồn (origins)
    configuration.addAllowedMethod("*"); // Cho phép tất cả các phương thức (GET, POST, PUT, DELETE, v.v.)
    configuration.addAllowedOriginPattern("*"); // Cho phép tất cả các origin patterns

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration); // Áp dụng CORS cho tất cả các endpoint
    return source;
  }

  /**
   * Cấu hình bộ lọc CORS cho ứng dụng.
   *
   * @return CorsFilter Bộ lọc CORS
   */
  @Bean
  public CorsFilter corsFilter() {
    return new CorsFilter(corsConfigurationSource());
  }

  /**
   * Cấu hình các yêu cầu HTTP cụ thể (trang index, sign-in, sign-up, home) và yêu cầu xác thực đối với các yêu cầu khác.
   *
   * @param http Cấu hình bảo mật HTTP
   * @throws Exception nếu có lỗi trong quá trình cấu hình
   */
}


