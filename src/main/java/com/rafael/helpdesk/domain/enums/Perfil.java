package com.rafael.helpdesk.domain.enums;

public enum Perfil {

	ADMIN(0, "ROLE_ADMIN"), CLIENTE(1, "ROLE_CLIENTE"), TECNICO(2, "ROLE_TECNICO");

	private Integer codigo;
	private String descricao;

	private Perfil(Integer codigo, String descricao) {
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
	public static Perfil toEnum(Integer codigo) {
		if (codigo == null) {
			return null; // Se codigo = nulo, vai retornar null
		}

		// Validando o codigo nos valores do Enum Perfil cadastrado, sendo igual,
		// retorna o Perfil
		Perfil[] valoresPerfil = Perfil.values();
		for (Perfil x : valoresPerfil) {
			if (codigo.equals(x.getCodigo())) {
				return x;
			}
		}

		// Caso nao seja nulo e nem o valor de codigo nao ser igual as valores da enum
		// Perfil, vai lançar uma Exception
		throw new IllegalArgumentException("Pérfil inválido!");
	}

}
