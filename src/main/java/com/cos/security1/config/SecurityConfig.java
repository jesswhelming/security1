package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;
//구글 로그인이 완료된 뒤의 후처리가 필요. 
//1.코드받기(인증), 2.엑세스토큰(권한)
//3. 사용자프로필 정보를 가져오고 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도함
//4-2 (이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소), 백화점몰 ->(vip등급)
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록된다.
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)  // pre, post, 어노테이션 활성화, 특정 주소 접근시 권한 및 인증을 위한 어노테이션 활성화
public class SecurityConfig{
	
	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;
	
	
	//해당 메서드의 리턴되는 오브젝트를 IoC로 등록해 준다.
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http.authorizeHttpRequests(authorize ->
                authorize
                        .requestMatchers("/user/**").authenticated()
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                        .anyRequest().permitAll()
        );
        
        //권한없는 페이지를 들어갈때 login페이지로 이동
        http
		.formLogin(form -> form
			.loginPage("/loginForm")
			.loginProcessingUrl("/login") //login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행해줌
			.permitAll()
		);
        
        http
        .oauth2Login((oauth2) -> oauth2
        .loginPage("/oauth2/authorization/google") // 권한 접근 실패 시 로그인 페이지로 이동
        .defaultSuccessUrl("http://localhost:8080") // 로그인 성공 시 이동할 페이지
        .failureUrl("/oauth2/authorization/google") // 로그인 실패 시 이동 페이지
        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
        .userService(principalOauth2UserService))
        .permitAll());
        // 구글 로그인이 완료된 뒤의 후 처리가 필요함. Tip. 코드X, (엑세스토큰 + 사용자프로필정보 O)
        //
        return http.build();
    }
}
