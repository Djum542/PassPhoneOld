package com.gdu.nhom1.shopproject.configuration;

import javax.servlet.http.HttpServletResponse;

import com.gdu.nhom1.shopproject.controllers.CartController;
import com.gdu.nhom1.shopproject.jwt.JwtTokenFilter;
//import com.gdu.nhom1.shopproject.repository.UserRepository;
import com.gdu.nhom1.shopproject.repository.UserRepositoryJwt;
import com.gdu.nhom1.shopproject.services.UserService;
import com.gdu.nhom1.shopproject.services.UserServiceJwt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {

	@Autowired private UserRepositoryJwt userRepo;
	
	@Autowired private JwtTokenFilter jwtTokenFilter;
	@Autowired
	private UserServiceJwt userService;
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(username -> userRepo.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found.")));
	}

//	@Bean
//	public PasswordEncoder passwordEncoder() {
//		return new BCryptPasswordEncoder();
//	}
	@Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
		
		http.authorizeRequests()
				//.antMatchers("/register**", "/", "/shop/**","login").permitAll()
				.antMatchers("/register**", "/", "/shop/**","/login","/auth/login", "/docs/**", "/users").permitAll()
				//.antMatchers("/users/**").hasRole("USER")
				.anyRequest().authenticated()
				.and()
				.formLogin()
				.loginPage("/login")
				.defaultSuccessUrl("/");
//				.and()
//				.exceptionHandling()
//				.accessDeniedPage("/403")
//				.and()
//				.formLogin()
//				.loginPage("/login") // Khi sử dụng phương thức post để đăng nhập, các thông tin đăng nhập (như
//				// tên đăng nhập và mật khẩu) sẽ được gửi đến đường dẫn "/login" được định nghĩa
//				// trong phương thức formLogin() của lớp SecurityConfig.
//				.successHandler(new SavedRequestAwareAuthenticationSuccessHandler())
//				.defaultSuccessUrl("/")
//				.permitAll()
//				.and()
//				.logout()
//				.invalidateHttpSession(true)
//				.clearAuthentication(true)
//				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//				.logoutSuccessHandler(logoutSuccessHandler())
//				.permitAll();;
//		http.build();
        http.exceptionHandling()
                .authenticationEntryPoint(
                    (request, response, ex) -> {
                        response.sendError(
                            HttpServletResponse.SC_UNAUTHORIZED,
                            ex.getMessage()
                        );
                    }
                );
        
		http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
private LogoutSuccessHandler logoutSuccessHandler() {
	return (request, response, authentication) -> {
		CartController.clearCart();
		response.sendRedirect("/login");
	};
}
//	@Bean
//	public DaoAuthenticationProvider authenticationProvider() {
//		DaoAuthenticationProvider auth = new DaoAuthenticationProvider();
//		auth.setUserDetailsService((UserDetailsService) userService);
//		auth.setPasswordEncoder(passwordEncoder());
//		return auth;
//	}
	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() throws Exception {
		return (web) -> web.ignoring().antMatchers("/resources/**", "/static/**", "/images/**", "/css/**", "/js/**",
				"/error");
	}// Bỏ xác minh các package đường dẫn này
//	@Bean
//	public UserDetailsService userDetailsService() {
//		UserDetails user =
//				User.withDefaultPasswordEncoder()
//						.username("user")
//						.password("password")
//						.roles("ADMIN")
//						.build();
//
//		return new InMemoryUserDetailsManager(user);
//	}
}
