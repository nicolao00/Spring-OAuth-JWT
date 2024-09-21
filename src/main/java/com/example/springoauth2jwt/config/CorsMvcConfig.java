package com.example.springoauth2jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
        corsRegistry.addMapping("/**")
                .exposedHeaders("Set-Cookie")
                // 서버 응답 헤더 중 'Set-Cookie' 헤더를 클라이언트에게 노출.
                // 브라우저는 보안 정책상 기본적으로 몇몇 헤더를 숨기는데, 쿠키를 전달하기 위해 해당 헤더를 노출.
                .allowedOrigins("http://localhost:3000");
    }
}
