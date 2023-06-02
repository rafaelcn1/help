package com.rafael.helpdesk.services.execptions;

public class ObjectNotFoundException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	//Metodo que recebe a mensagem e a causa da Exception
	public ObjectNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}

	//Metodo que recebe a mensagem da Exception
	public ObjectNotFoundException(String message) {
		super(message);
	}
	
	

}
