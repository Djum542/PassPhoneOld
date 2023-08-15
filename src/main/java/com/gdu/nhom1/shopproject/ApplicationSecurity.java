package com.gdu.nhom1.shopproject;

import javax.servlet.http.HttpServletResponse;

import com.gdu.nhom1.shopproject.controllers.CartController;
import com.gdu.nhom1.shopproject.jwt.JwtTokenFilter;
import com.gdu.nhom1.shopproject.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;


@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private JwtTokenFilter jwtTokenFilter;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(username -> userRepo.findByemail(username)
				.orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found.")));
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
		
		http.authorizeRequests()
				.antMatchers("/auth/login", "/docs/**", "/users","/","/home","/shop/**","/register/**","/login/**","/jsonpro/**").permitAll()
				.anyRequest().authenticated()
				.and()
				.formLogin()
				.loginPage("/login")
				.defaultSuccessUrl("/shop");
		
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
	@Bean
    public WebSecurityCustomizer webSecurityCustomizer() throws Exception {
        return (web) -> web.ignoring().antMatchers("/resources/**", "/static/**", "/images/**", "/css/**", "/js/**",
                "/error");
    }// Bỏ xác minh các package đường dẫn này
}
