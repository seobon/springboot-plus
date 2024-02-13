package lecture.springbootsecurity.config;

import lecture.springbootsecurity.security.CustomAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.Security;
import java.util.Arrays;

@Configuration // 스프링 설정 클래스다
@EnableWebSecurity // Spring security 를 사용한다
public class WebSecurityConfig {
    @Autowired
    CustomAuthFilter customAuthFilter;

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // 3.X.X 버전
    @Bean // 스프링 컨테이너에서 관리
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 스프링 시큐리티 적용하면 기본적으로 모든 경로에 인증이 있어야 접근이 가능해짐.
        // 특정 경로에서 인증 없이 접근 할 수 있도록 설정.
        http
                .cors(Customizer.withDefaults())
                .csrf(CsrfConfigurer::disable) // post, put 요청을 허용
                .authorizeHttpRequests(authorize -> authorize
                                .requestMatchers("/auth/**").permitAll()
//                        .requestMatchers("/auth/**").hasRole("ADMIN")
                                .anyRequest().authenticated()
                        // ("/auth/signin", "/auth/signup")
                        // => ("/auth/**").permitAll()
                );
        // .permitAll() : 권한 없이 접속 가능하다.
        // .authenticated() : 로그인이 필요하다.
        // .anyRequest().authenticated() : (위 주소를 제외한) 나머지 모든 주소는 모두 로그인이 필요하다.
        // 그러므로 가장 마지막에 작성.
        // .hasRole("권한? ex. ADMIN"): 특정 권한이 있어야 접속 가능.

        // 만들어둔 custom 필터 등록
        http.addFilterAfter(customAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
// 2.X.X 버전이므로 헷갈리지말고 구글링시 3.X.X 버전도 함께 검색
//public class WebSecurityConfig extends SecurityConfigurerAdapter {
//    public config() {}
//}

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // cors 설정
        config.setAllowCredentials(true); // 실제 응답을 보낼 때, 브라우저에게 자격 증명과 함께 요청을 보낼 수 있도록 허용합니다.
        config.setAllowedOriginPatterns(Arrays.asList("*")); // 모든 원본에서의 요청을 허용합니다.
        config.setAllowedMethods(Arrays.asList("HEAD","POST","GET","DELETE","PUT", "PATCH")); // 허용할 HTTP 메서드를 설정합니다.
        config.setAllowedHeaders(Arrays.asList("*")); // 모든 헤더의 요청을 허용합니다.


        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config); // 모든 경로에 대해 위에서 설정한 CORS 설정을 적용합니다.

        return source;
    };
}
