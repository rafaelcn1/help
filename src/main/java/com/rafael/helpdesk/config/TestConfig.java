package com.rafael.helpdesk.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.rafael.helpdesk.services.DBService;

@Configuration
@Profile("test")
public class TestConfig {
	
	@Autowired
	private DBService dbService;
	
	@Bean //Toda vez que o perfil test estiver ativo, irá chamar esse metodo automatico
	public void instanciaDB() {
		dbService.instanciaDB();
	}

}
