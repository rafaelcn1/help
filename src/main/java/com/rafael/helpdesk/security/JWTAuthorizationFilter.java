package com.rafael.helpdesk.security;

import java.io.IOException;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private JWTUtil jwtUtil;

	private UserDetailsService userDetailsService;

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil,
			UserDetailsService userDetailsService) {
		super(authenticationManager);
		this.jwtUtil = jwtUtil;
		this.userDetailsService = userDetailsService;
	}

	public JWTUtil getJwtUtil() {
		return jwtUtil;
	}

	public void setJwtUtil(JWTUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	public UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// Capturando o Header da requisição
		String header = request.getHeader("Authorization");

		// Validação dif null e se header começa com o Bearer
		if (header != null && header.startsWith("Bearer ")) {
			// Pegando apenas o token, sem o "Bearer "
			UsernamePasswordAuthenticationToken authToken = getAuthentication(header.substring(7));
			if (authToken != null) {
				// definindo a autenticação do usuário atual no contexto de segurança
				// substitui a autenticação atual do usuário pelo objeto authToken, permitindo
				// usuário após o login
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		chain.doFilter(request, response);

	}

	private UsernamePasswordAuthenticationToken getAuthentication(String token) {
		if (jwtUtil.tokenValido(token)) {
			// Capturando nome do usuário
			String username = jwtUtil.getUsername(token);
			// Carregando os dados do usuario
			UserDetails details = userDetailsService.loadUserByUsername(username);

			// Retornando um UsernamePasswordAuthenticationToken, onde vai ser passado
			// apenas o nome do usuário, não vai passar a senha, por isso o null e passando
			// a lista do perfil do usuário
			return new UsernamePasswordAuthenticationToken(details.getUsername(), null, details.getAuthorities());
		}
		
		return null;
	}

}
