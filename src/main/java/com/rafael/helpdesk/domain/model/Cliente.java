package com.rafael.helpdesk.domain.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.persistence.Entity;
import javax.persistence.OneToMany;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.rafael.helpdesk.domain.enums.Perfil;
import com.rafael.helpdesk.dtos.ClienteDTO;

@Entity
public class Cliente extends Pessoa implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	@JsonIgnore // Nesse caso é para evitar o loop infinito, por causa da Serialização
	@OneToMany(mappedBy = "cliente") // Um cliete para muitos chamados, o nome cliente é o nome do field cliente do
										// tipo Cliente na classe chamado
	private List<Chamado> chamados = new ArrayList<>();

	public Cliente() {
		super();
		addPerfis(Perfil.CLIENTE); // Sempre que um cliente for adicionado, será adicionado auto o perfil cliente
	}

	public Cliente(Integer id, String nome, String cpf, String email, String senha) {
		super(id, nome, cpf, email, senha);
		addPerfis(Perfil.CLIENTE); // Sempre que um cliente for adicionado, será adicionado auto o perfil cliente
	}

	public Cliente(ClienteDTO clienteDTO) {
		super();
		this.id = clienteDTO.getId();
		this.nome = clienteDTO.getNome();
		this.cpf = clienteDTO.getCpf();
		this.email = clienteDTO.getEmail();
		this.senha = clienteDTO.getSenha();
		this.perfis = clienteDTO.getPerfis().stream().map(x -> x.getCodigo()).collect(Collectors.toSet());
		this.dataCriacao = clienteDTO.getDataCriacao();
	}
	
	public Cliente(String id) {
	    this.id = Integer.parseInt(id);
	}

	public List<Chamado> getChamados() {
		return chamados;
	}

	public void setChamados(List<Chamado> chamados) {
		this.chamados = chamados;
	}

}
