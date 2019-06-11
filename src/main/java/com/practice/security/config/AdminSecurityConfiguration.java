package com.practice.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

@Configuration
@Order(1)
public class AdminSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.antMatcher("/support/admin/**").addFilter(getDigestAuthenticationFilter()).exceptionHandling()
				.authenticationEntryPoint(getDigestEntryPoint()).and().authorizeRequests()
				.antMatchers("/support/admin/**").hasRole("ADMIN");
	}

	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("admin1").password("password1").roles("USER").and().withUser("admin2")
				.password("password2").roles("ADMIN");
	}

	public DigestAuthenticationFilter getDigestAuthenticationFilter() throws Exception {
		DigestAuthenticationFilter authenticationFilter = new DigestAuthenticationFilter();
		authenticationFilter.setAuthenticationEntryPoint(getDigestEntryPoint());
		authenticationFilter.setUserDetailsService(userDetailsServiceBean());
		return authenticationFilter;
	}

	@Override
	@Bean
	public UserDetailsService userDetailsServiceBean() throws Exception {
		return super.userDetailsServiceBean();
	}

	@Bean
	public PasswordEncoder encoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	private DigestAuthenticationEntryPoint getDigestEntryPoint() {
		DigestAuthenticationEntryPoint entryPoint = new DigestAuthenticationEntryPoint();
		entryPoint.setKey("ShagunBakliwalKey");
		entryPoint.setRealmName("digest-admin-realm");
		entryPoint.setOrder(1);
		entryPoint.setNonceValiditySeconds(300);
		return entryPoint;
	}
}
