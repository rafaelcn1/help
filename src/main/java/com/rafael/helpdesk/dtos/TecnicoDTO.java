package com.rafael.helpdesk.dtos;

import java.io.Serializable;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.rafael.helpdesk.domain.enums.Perfil;
import com.rafael.helpdesk.domain.model.Tecnico;

import javax.validation.constraints.NotNull;

public class TecnicoDTO implements Serializable {

	/*
	 * Classe criada para boas praticas, para que a Entidade (classe) esteja
	 * expostas
	 * 
	 */

	private static final long serialVersionUID = 1L;
	protected Integer id;
	@NotNull(message = "Campo NOME é requerido!")
	protected String nome;
	@NotNull(message = "Campo CPF é requerido!")
	protected String cpf;
	@NotNull(message = "Campo EMAIL é requerido!")
	protected String email;
	@NotNull(message = "Campo SENHA é requerido!")
	protected String senha;
	protected Set<Integer> perfis = new HashSet<>();

	@JsonFormat(pattern = "dd/MM/yyyy") // Formato de data no banco conforme o nosso pattern
	protected LocalDate dataCriacao = LocalDate.now();

	public TecnicoDTO() {
		super();
		addPerfis(Perfil.CLIENTE);
		
	}

	public TecnicoDTO(Tecnico tecnico) {
		super();
		this.id = tecnico.getId();
		this.nome = tecnico.getNome();
		this.cpf = tecnico.getCpf();
		this.email = tecnico.getEmail();
		this.senha = tecnico.getSenha();
		this.perfis = tecnico.getPerfis().stream().map(x -> x.getCodigo()).collect(Collectors.toSet());
		this.dataCriacao = tecnico.getDataCriacao();
		addPerfis(Perfil.TECNICO);
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public String getCpf() {
		return cpf;
	}

	public void setCpf(String cpf) {
		this.cpf = cpf;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getSenha() {
		return senha;
	}

	public void setSenha(String senha) {
		this.senha = senha;
	}

	public Set<Perfil> getPerfis() {
		return perfis.stream().map(x -> Perfil.toEnum(x)).collect(Collectors.toSet());
	}

	public void addPerfis(Perfil perfil) {
		this.perfis.add(perfil.getCodigo());
	}

	public LocalDate getDataCriacao() {
		return dataCriacao;
	}

	public void setDataCriacao(LocalDate dataCriacao) {
		this.dataCriacao = dataCriacao;
	}

}
