package com.rafael.helpdesk.services;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.rafael.helpdesk.domain.enums.Perfil;
import com.rafael.helpdesk.domain.enums.Prioridade;
import com.rafael.helpdesk.domain.enums.Status;
import com.rafael.helpdesk.domain.model.Chamado;
import com.rafael.helpdesk.domain.model.Cliente;
import com.rafael.helpdesk.domain.model.Tecnico;
import com.rafael.helpdesk.repositories.ChamadoRepository;
import com.rafael.helpdesk.repositories.ClienteRepository;
import com.rafael.helpdesk.repositories.TecnicoRepository;

@Service
public class DBService {

	@Autowired
	private TecnicoRepository tecnicoRepository;

	@Autowired
	private ClienteRepository clienteRepository;

	@Autowired
	private ChamadoRepository chamadoRepository;
	
	@Autowired
	BCryptPasswordEncoder passwordEncoder;

	public void instanciaDB() {
		// Toda vez que for iniciado o sistema, será criado esse tecnico
		Tecnico tec1 = new Tecnico(null, "Rafael Cunha", "05196131477", "rafaelcn1@hotmail.com", passwordEncoder.encode("123"));
		tec1.addPerfis(Perfil.ADMIN); // Adicionando o perfil admin ao tec1

		Cliente cli1 = new Cliente(null, "José Lobo", "64305931850", "jose@gmail.com", passwordEncoder.encode("123"));
		Chamado c1 = new Chamado(null, Prioridade.MEDIA, Status.ABERTO, "Chamado 01", "Primeiro Chamado", tec1, cli1);

		tecnicoRepository.saveAll(Arrays.asList(tec1));
		clienteRepository.saveAll(Arrays.asList(cli1));
		chamadoRepository.saveAll(Arrays.asList(c1));
	}

}
