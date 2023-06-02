package com.rafael.helpdesk.domain.enums;

public enum Status {

	ABERTO(0, "ABERTO"), ANDAMENTO(1, "ANDAMENTO"), ENCERRADO(2, "ENCERRADO");

	private Integer codigo;
	private String descricao;

	private Status(Integer codigo, String descricao) {
		this.codigo = codigo;
		this.descricao = descricao;
	}

	public Integer getCodigo() {
		return codigo;
	}

	public void setCodigo(Integer codigo) {
		this.codigo = codigo;
	}

	public String getDescricao() {
		return descricao;
	}

	public void setDescricao(String descricao) {
		this.descricao = descricao;
	}

	// Metodo para validar codigo do perfil
	public static Status toEnum(Integer codigo) {
		if (codigo == null) {
			return null; // Se codigo = nulo, vai retornar null
		}

		// Validando o codigo nos valores do Enum Perfil cadastrado, sendo igual,
		// retorna o Perfil
		Status[] valoresPerfil = Status.values();
		for (Status x : valoresPerfil) {
			if (codigo.equals(x.getCodigo())) {
				return x;
			}
		}

		// Caso nao seja nulo e nem o valor de codigo nao ser igual as valores da enum
		// Perfil, vai lançar uma Exception
		throw new IllegalArgumentException("Status inválido!");
	}

}
