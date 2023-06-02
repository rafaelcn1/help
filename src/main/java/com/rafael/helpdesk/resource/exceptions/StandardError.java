package com.rafael.helpdesk.resource.exceptions;

import java.io.Serializable;

public class StandardError implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	/*
	 * Classe para pegar os valores da exceção
	 */

	private Long timestamp; // Hora do error
	private Integer status; // Status do error
	private String error; // O error em si
	private String message; // A mensagem que foi criada
	private String path; // a url que tentou acessar;

	public StandardError() {
		super();
		// TODO Auto-generated constructor stub
	}

	public StandardError(Long timestamp, Integer status, String error, String message, String path) {
		super();
		this.timestamp = timestamp;
		this.status = status;
		this.error = error;
		this.message = message;
		this.path = path;
	}

	public Long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Long timestamp) {
		this.timestamp = timestamp;
	}

	public Integer getStatus() {
		return status;
	}

	public void setStatus(Integer status) {
		this.status = status;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}

}
