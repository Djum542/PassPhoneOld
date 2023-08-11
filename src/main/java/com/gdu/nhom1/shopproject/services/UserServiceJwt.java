package com.gdu.nhom1.shopproject.services;

import javax.transaction.Transactional;

import com.gdu.nhom1.shopproject.models.Role;
import com.gdu.nhom1.shopproject.models.User;
import com.gdu.nhom1.shopproject.repository.UserRepositoryJwt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserServiceJwt {
	@Autowired private UserRepositoryJwt repo;
	@Autowired private PasswordEncoder passwordEncoder;

	public User save(User user) {
		String rawPassword = user.getPassword();
		String encodedPassword = passwordEncoder.encode(rawPassword);
		user.setPassword(encodedPassword);

		return repo.save(user);
	}
//	public UserDetails loadUserByUserName(String username) throws UsernameNotFoundException {
//		Optional<User> user = repo.findByEmail(username);
//		if (user == null){
//			throw new UsernameNotFoundException("Invalid user and password");
//		}
//		return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), mapRolesToAuthorities(user.getRoles()) );
//	}
	private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles){
		return roles.stream().map(role->new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
	}
//	public List<User> findAll(){
//		return repo.findAllUserNonAdmin();
//	}
	public void removeUserByid(int id){
		repo.deleteById(id);
	}
	public void updateUserName(User user){
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		user.setRoles(new HashSet<>());
		repo.save(user);
	}
	public Optional<User> findByEmail(String email) {
		return repo.findByEmail(email);
	}
}
