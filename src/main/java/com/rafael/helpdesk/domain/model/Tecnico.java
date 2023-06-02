package com.rafael.helpdesk.domain.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.rafael.helpdesk.dtos.TecnicoDTO;

import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;

@Entity
public class Tecnico extends Pessoa implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@JsonIgnore // Nesse caso é para evitar o loop infinito, por causa da Serialização
	@OneToMany(mappedBy = "tecnico") // Um téncico para muitos chamados, o nome tecnico é o nome do field tecnico, do
										// Tipo Tecnico na classe chamado
	private List<Chamado> chamados = new ArrayList<>();

	public Tecnico() {
		super();
	}

	public Tecnico(TecnicoDTO tecnicoDTO) {
		super();
		this.id = tecnicoDTO.getId();
		this.nome = tecnicoDTO.getNome();
		this.cpf = tecnicoDTO.getCpf();
		this.email = tecnicoDTO.getEmail();
		this.senha = tecnicoDTO.getSenha();
		this.perfis = tecnicoDTO.getPerfis().stream().map(x -> x.getCodigo()).collect(Collectors.toSet());
		this.dataCriacao = tecnicoDTO.getDataCriacao();
	}

	public Tecnico(Integer id, String nome, String cpf, String email, String senha) {
		super(id, nome, cpf, email, senha);
	}

	public List<Chamado> getChamados() {
		return chamados;
	}

	public void setChamados(List<Chamado> chamados) {
		this.chamados = chamados;
	}

}
