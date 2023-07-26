package com.rafael.helpdesk.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.rafael.helpdesk.security.JWTAuthenticationFilter;
import com.rafael.helpdesk.security.JWTAuthorizationFilter;
import com.rafael.helpdesk.security.JWTUtil;

@EnableWebSecurity // Habilita a configuração de segurança do Spring Security.
@EnableGlobalMethodSecurity(prePostEnabled = true) // Habilita a segurança a nível de método com base em anotações.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// Array contendo os caminhos públicos que não exigem autenticação.
	private static final String[] PUBLIC_MATCHERS = { "/h2/**" };

	@Autowired
	private Environment env;
	@Autowired
	private JWTUtil jwtUtil;
	@Autowired
	private UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// Verifica se o perfil ativo é "dev". Se sim, desabilita a proteção contra o frameOptions para permitir o acesso ao console H2.
		if (Arrays.asList(env.getActiveProfiles()).contains("dev")) {
			http.headers().frameOptions().disable();
		}

		// Desabilita a proteção CSRF (Cross-Site Request Forgery) que não é necessária para APIs que utilizam autenticação via token JWT.
		http.cors().and().csrf().disable();

		// Adiciona filtros personalizados ao pipeline de segurança para autenticação e autorização usando tokens JWT.
		http.addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtUtil));
		http.addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtUtil, userDetailsService));

		// Configura as regras de autorização para os endpoints da aplicação.
		// Os endpoints definidos em PUBLIC_MATCHERS serão permitidos sem necessidade de autenticação.
		// Todos os outros endpoints precisarão de autenticação.
		http.authorizeRequests().antMatchers(PUBLIC_MATCHERS).permitAll().anyRequest().authenticated();

		// Configura a política de gerenciamento de sessão para STATELESS (sem estado).
		// Como a aplicação utiliza autenticação via token JWT, não é necessário criar ou manter sessões no servidor.
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// Configura o serviço de autenticação personalizado (UserDetailsService) e o algoritmo de criptografia da senha.
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		// Configura as permissões padrão para CORS (Cross-Origin Resource Sharing).
		CorsConfiguration configuration = new CorsConfiguration().applyPermitDefaultValues();
		configuration.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS"));
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		// Cria e retorna um objeto BCryptPasswordEncoder, que é o algoritmo utilizado para criptografar senhas.
		return new BCryptPasswordEncoder();
	}
}
