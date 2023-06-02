package com.rafael.helpdesk.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rafael.helpdesk.dtos.CredenciaisDTO;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager; // Principal interface para autenticação
	private JWTUtil jwtUtil;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
		this.authenticationManager = authenticationManager;
		this.jwtUtil = jwtUtil;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		try {
			// ler o conteúdo do corpo da requisição HTTP e convertê-lo para um objeto do
			// tipo CredenciaisDTO.
			CredenciaisDTO creds = new ObjectMapper().readValue(request.getInputStream(), CredenciaisDTO.class);
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
					creds.getEmail(), creds.getSenha(), new ArrayList<>());
			return authenticationManager.authenticate(authenticationToken);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		// Resultado da autenticação
		String username = ((UserSS) authResult.getPrincipal()).getUsername();
		// Gerando o token
		String token = jwtUtil.generateToken(username);

		// Para pegar o token depois
		response.setHeader("access-control-expose-headers", "Authorization");
		response.setHeader("Authorization", "Bearer " + token);

	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		response.setStatus(401);
		// Tipo do conteudo
		response.setContentType("application/json");

		// Jogar a resposta em formato JSON
		response.getWriter().append(json());
	}

	private CharSequence json() {
		long date = new Date().getTime();
		return "{" + "\"timestamp\": " + date + ", " + "\"status\": 401, " + "\"error\": \"Não autorizado\", "
				+ "\"message\": \"Email ou senha inválidos\", " + "\"path\": \"/login\"}";
	}

}
