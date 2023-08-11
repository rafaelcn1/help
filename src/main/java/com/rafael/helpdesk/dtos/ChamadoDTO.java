package com.rafael.helpdesk.dtos;

import java.io.Serializable;
import java.time.LocalDate;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.rafael.helpdesk.domain.enums.Prioridade;
import com.rafael.helpdesk.domain.enums.Status;
import com.rafael.helpdesk.domain.model.Chamado;
import com.rafael.helpdesk.domain.model.Cliente;
import com.rafael.helpdesk.domain.model.Tecnico;

public class ChamadoDTO implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private Integer id;
	@JsonFormat(pattern = "dd/MM/yyyy") // Formato de data no banco conforme o nosso pattern
	private LocalDate dataAbertura;
	@JsonFormat(pattern = "dd/MM/yyyy") // Formato de data no banco conforme o nosso pattern
	private LocalDate dataFechamento;
	private Prioridade prioridade;
	private Status status;
	private String titulo;
	private String observacoes;
	private Tecnico tecnico;
	private Cliente cliente;

	public ChamadoDTO() {
		super();
	}

	public ChamadoDTO(Chamado chamado) {
		super();
		this.id = chamado.getId();
		this.dataAbertura = chamado.getDataAbertura();
		this.dataFechamento = chamado.getDataFechamento();
		this.prioridade = chamado.getPrioridade();
		this.status = chamado.getStatus();
		this.titulo = chamado.getTitulo();
		this.observacoes = chamado.getObservacoes();
		this.tecnico = chamado.getTecnico();
		this.cliente = chamado.getCliente();
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public LocalDate getDataAbertura() {
		return dataAbertura;
	}

	public void setDataAbertura(LocalDate dataAbertura) {
		this.dataAbertura = dataAbertura;
	}

	public LocalDate getDataFechamento() {
		return dataFechamento;
	}

	public void setDataFechamento(LocalDate dataFechamento) {
		this.dataFechamento = dataFechamento;
	}

	public Prioridade getPrioridade() {
		return prioridade;
	}

	public void setPrioridade(Prioridade prioridade) {
		this.prioridade = prioridade;
	}

	public Status getStatus() {
		return status;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	public String getTitulo() {
		return titulo;
	}

	public void setTitulo(String titulo) {
		this.titulo = titulo;
	}

	public String getObservacoes() {
		return observacoes;
	}

	public void setObservacoes(String observacoes) {
		this.observacoes = observacoes;
	}
	
	public Tecnico getTecnico() {
	    return tecnico;
	}

//	public void setTecnico(String tecnicoId) {
//	    this.tecnico = new Tecnico(tecnicoId);
//	}
	
	

	public void setTecnico(Tecnico tecnico) {
		this.tecnico = tecnico;
	}

	public Cliente getCliente() {
		return cliente;
	}

	public void setCliente(Cliente cliente) {
		this.cliente = cliente;
	}
	
//	public void setCliente(String clienteId) {
//	    this.cliente = new Cliente(clienteId);
//	}

}
