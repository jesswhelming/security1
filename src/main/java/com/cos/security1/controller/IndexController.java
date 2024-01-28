package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

//import com.cos.security1.config.auth.PrincipalDetails;
//import com.cos.security1.model.User;
//import com.cos.security1.repository.UserRepository;

@Controller
public class IndexController {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping("/test/login")
	public @ResponseBody String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) { //DI의존성 주입
		System.out.println("/test/login =========");
		System.out.println("authentication Obj : "+authentication.getPrincipal());
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication user : " + principalDetails.getUser());
	
		return "세션 정보 확인하기";
	}

	@GetMapping("/test/oauth/login")
	public @ResponseBody String testLogin(
			Authentication authentication,
			@AuthenticationPrincipal OAuth2User oauth) { //DI(의존성 주입)
		System.out.println("/test/oauth/login =========");
		System.out.println("authentication Obj : "+authentication.getPrincipal());
		OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
		System.out.println("authentication : " + oAuth2User.getAttributes());
		System.out.println("oauth2User : " + oauth.getAttributes());
		return "OAuth 세션 정보 확인하기";
	}
	@GetMapping({ "", "/" })
	public @ResponseBody String index() {
		return "인덱스 페이지입니다.";
	}

	
	//OAuth 로그인을 해도 PrincipalDetails
	//일반 로그인을 해도 PrincipalDetails
	@GetMapping("/user")
	public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("Principal : " + principalDetails.getUser());
		// iterator 순차 출력 해보기
//		Iterator<? extends GrantedAuthority> iter = principal.getAuthorities().iterator();
//		while (iter.hasNext()) {
//			GrantedAuthority auth = iter.next();
//			System.out.println(auth.getAuthority());
//		}

		return "유저 페이지입니다.";
	}

	
//	@GetMapping("/user")
//	public @ResponseBody String user() {
//		return "유저 페이지입니다.";
//	}
	
	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "어드민 페이지입니다.";
	}
	
	//@PostAuthorize("hasRole('ROLE_MANAGER')")
	//@PreAuthorize("hasRole('ROLE_MANAGER')")
	@Secured("ROLE_MANAGER")
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "매니저 페이지입니다.";
	}

	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}


	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@PostMapping("/join")
	public String join(User user) {
		System.out.println(user);
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		userRepository.save(user); // 회원가입 잘됨. 비밀번호 : 1234 => 시큐리티로 ㄱ로그인을 할 수 없음. 이유는 패스워드가 암호화가 안되어있기때문 
		return "redirect:/loginForm";
	}

	@Secured("ROLE_ADMIN")
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "개인정보";
	}
	
	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터정보";
	}
	/*
	 * @PostMapping("/joinProc") public String joinProc(User user) {
	 * System.out.println("회원가입 진행 : " + user); String rawPassword =
	 * user.getPassword(); String encPassword =
	 * bCryptPasswordEncoder.encode(rawPassword); user.setPassword(encPassword);
	 * user.setRole("ROLE_USER"); userRepository.save(user); return "redirect:/"; }
	 */
}