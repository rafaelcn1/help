package com.rafael.helpdesk.security;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JWTUtil {

	@Value("${jwt.expiration}") // valor do parametro que está no arquivo applucation.properties
	private Long expiration;

	@Value("${jwt.secret}") // valor do parametro que está no arquivo applucation.properties
	private String secret;

	public String generateToken(String email) {
		return Jwts.builder().setSubject(email).setExpiration(new Date(System.currentTimeMillis() + expiration))
				.signWith(SignatureAlgorithm.HS512, secret.getBytes()).compact();

	}

	public String getUsername(String token) {
		Claims claims = getClaims(token);
		if (claims != null) {
			return claims.getSubject();
		}
		return null;
	}

	/**
	 * Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token).getBody(),
	 * estamos utilizando a biblioteca JWT (JSON Web Token) para processar um token.
	 * Vou dividir em etapas para facilitar a compreensão:
	 * 
	 * Jwts.parser(): Aqui estamos criando um objeto de parser JWT. Essa classe é
	 * responsável por analisar e validar um token JWT.
	 * 
	 * setSigningKey(secret.getBytes()): Estamos configurando a chave de assinatura
	 * usada para validar o token. secret é uma variável que deve conter a chave
	 * secreta compartilhada entre a geração e a validação do token.
	 * 
	 * parseClaimsJws(token): Estamos passando o token para o parser processar. Esse
	 * método irá analisar o token, verificar sua validade e retornar um objeto que
	 * contém as afirmações (claims) contidas nele.
	 * 
	 * .getBody(): Com esse método, estamos obtendo o corpo do token, ou seja, as
	 * afirmações contidas nele. Essas afirmações geralmente são armazenadas em um
	 * objeto estruturado, como um mapa ou um objeto JSON.
	 */
	// "Claims" são informações contidas em um token de autenticação.
	private Claims getClaims(String token) {
		try {
			// analisar um token, verificar sua validade e obter as afirmações contidas nele
			return Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token).getBody();
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * verifica se um token de autenticação é válido. Ele verifica se o token foi
	 * decodificado corretamente, se contém um nome de usuário válido e se a data de
	 * expiração do token ainda não foi alcançada
	 */
	public boolean tokenValido(String token) {
		Claims claims = getClaims(token);
		if (claims != null) {
			String username = claims.getSubject();
			Date expirationDate = claims.getExpiration();
			Date now = new Date(System.currentTimeMillis());

			if (username != null && expirationDate != null && now.before(expirationDate)) {
				return true;
			}
		}
		return false;
	}
}
