package com.example.login.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import com.example.login.service.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

	@Autowired
	private UserDetailsServiceImpl userDetailsService;
	
	@Autowired
	private DataSource dataSource;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
		return bCryptPasswordEncoder;
	}
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		// set and init service to search in database.
		//Set passwordEndcoder
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
		
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http.csrf().disable();
		
		//pages not require to login
		http.authorizeRequests().antMatchers("/", "/login", "/logout").permitAll();
		
		//page /userInfor require to login with role is ADMIN or USER
		//if has not loged in, redirect to /login
		http.authorizeRequests().antMatchers("/userInfo").access("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')");
		
		//page only for ADMIN
		http.authorizeRequests().antMatchers("/admin").access("hasRole('ROLE_ADMIN')");
		
		
		//When user loged in with role is USER
		//but need to access to page require role is ADMIN
		//exception will be throw out
		http.authorizeRequests().and().exceptionHandling().accessDeniedPage("/403");
		
		//config login form
		
		http.authorizeRequests().and().formLogin()
			//Sucmit url of login page
			.loginPage("/login")
			.defaultSuccessUrl("/userAccountInfo")
			.failureUrl("/login?error=true")
			.usernameParameter("usermane")
			.passwordParameter("password")
			
			//config for logout page
			.and().logout().logoutUrl("/logout").logoutSuccessUrl("/logoutSuccessUrl");
		//Remember me config
		http.authorizeRequests().and()
			.rememberMe().tokenRepository(this.persistentTokenRepository())
			.tokenValiditySeconds(24*60*60);
		}
	@Bean
	public PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl db = new JdbcTokenRepositoryImpl();
		db.setDataSource(dataSource);
		return db;
	}
	
}
