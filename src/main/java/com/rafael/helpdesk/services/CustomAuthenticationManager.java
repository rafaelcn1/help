package com.rafael.helpdesk.services;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CustomAuthenticationManager implements AuthenticationManager {

	private UserDetailsService userDetailsService;
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public CustomAuthenticationManager(UserDetailsService userDetailsService,
			BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.userDetailsService = userDetailsService;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		String password = authentication.getCredentials().toString();

		// Obter os detalhes do usuário do UserDetailsService
		UserDetails userDetails = userDetailsService.loadUserByUsername(username);
		

		// Verificar se a senha está correta
		if (bCryptPasswordEncoder.matches(password, userDetails.getPassword())) {
			return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
		} else {
			throw new BadCredentialsException("Credenciais inválidas");
		}
	}

	

}
