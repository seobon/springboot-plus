package lecture.springbootsecurity.security;
// 1. 세션 기반 인증 방식
// -- 로그인에 성공 > session 에 userId 저장
// -- 로그인 여부를 판단하고 싶을 때 > session 에 userId 가 있는지 없는지에 따라
// ---- 존재하면, 로그인을 한 사람. 존재하지 않으면 로그인을 하지 않은 사람

// 2. jwt token 기반 인증 방식도 해볼 예정

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class CustomAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            HttpSession session = request.getSession();
            log.warn("session id {}", session.getId());
            Object userId = session.getAttribute("userId");

            if(userId != null){
                // 1. 사용자 정보를 담는 공간 (토큰) 생성
                Authentication authentication = new UsernamePasswordAuthenticationToken(String.valueOf(userId), AuthorityUtils.NO_AUTHORITIES);

                // 2. SecurityContextHolder 에 authentication 정보 set
                // SecurityContextHolder : 클라이언트가 요청을 하고 응답을 받기 전까지 클라이언트의 정보(auth)를 일시적으로 담아둘 수 있는 공간
                SecurityContextHolder.getContext().setAuthentication(authentication);
//                SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            }
        } catch (Exception e){
            log.error("filter error {}", e.getMessage());
        }
        filterChain.doFilter(request, response);
    }
}
