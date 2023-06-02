package com.rafael.helpdesk.resource.exceptions;

import java.io.Serializable;

public class FieldMessage implements Serializable {

	private static final long serialVersionUID = 1L;

	private String field;
	private String defaultMessage;

	public FieldMessage() {
		super();
	}

	public FieldMessage(String field, String defaultMessage) {
		super();
		this.field = field;
		this.defaultMessage = defaultMessage;
	}

	public String getField() {
		return field;
	}

	public void setField(String field) {
		this.field = field;
	}

	public String getDefaultMessage() {
		return defaultMessage;
	}

	public void setDefaultMessage(String defaultMessage) {
		this.defaultMessage = defaultMessage;
	}

}
