package com.rafael.helpdesk.services.execptions;

public class DataIntegrityViolationException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	//Metodo que recebe a mensagem e a causa da Exception
	public DataIntegrityViolationException(String message, Throwable cause) {
		super(message, cause);
	}

	//Metodo que recebe a mensagem da Exception
	public DataIntegrityViolationException(String message) {
		super(message);
	}
	
	

}
