package com.cos.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.security1.model.User;

//CRUD 함수를 JpaRepository가 들고 있음
//@Repository라는 어노테이션이 없어도 Ioc 된다. 이유는 JpaRepository를 상속했기 때문 
public interface UserRepository extends JpaRepository<User, Integer>{
	//findBy규칙 -> Username문법  //JPA name 함수 검색
	// select * from user where username = 1?
	public User findByUsername(String username);

	// select * from user where email = 1?  
	public User findByEmail(String email);
	
}
