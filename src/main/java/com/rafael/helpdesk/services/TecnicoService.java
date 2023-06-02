package com.rafael.helpdesk.services;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.rafael.helpdesk.domain.model.Pessoa;
import com.rafael.helpdesk.domain.model.Tecnico;
import com.rafael.helpdesk.dtos.TecnicoDTO;
import com.rafael.helpdesk.repositories.PessoaRepository;
import com.rafael.helpdesk.repositories.TecnicoRepository;
import com.rafael.helpdesk.services.execptions.DataIntegrityViolationException;
import com.rafael.helpdesk.services.execptions.ObjectNotFoundException;

import jakarta.validation.Valid;

@Service
public class TecnicoService {

	/*
	 * Classe para conversar com o banco
	 */

	@Autowired
	TecnicoRepository tecnicoRepository;

	@Autowired
	PessoaRepository pessoaRepository;
	
	@Autowired
	BCryptPasswordEncoder passwordEncoder;

	public Tecnico findById(Integer id) {
		Optional<Tecnico> findById = tecnicoRepository.findById(id);
		return findById.orElseThrow(() -> new ObjectNotFoundException("Objeto do ID: " + id + " - Não encontrado!"));
	}

	public List<Tecnico> findAll() {
		return tecnicoRepository.findAll();
	}

	public Tecnico create(TecnicoDTO tecnicoDTO) {
		tecnicoDTO.setId(null); // Por questão de segurança, o id sempre vai vir nulo, senao irar atualizar o
								// que já existe

		// Setando a senha do técnico cryptografada
		tecnicoDTO.setSenha(passwordEncoder.encode(tecnicoDTO.getSenha()));
		validarCpfEEmail(tecnicoDTO);

		Tecnico novoTecnico = new Tecnico(tecnicoDTO);
		return tecnicoRepository.save(novoTecnico);
	}

	private void validarCpfEEmail(TecnicoDTO tecnicoDTO) {
		Optional<Pessoa> tecnico = pessoaRepository.findByCpf(tecnicoDTO.getCpf());

		if (tecnico.isPresent() && tecnico.get().getId() != tecnicoDTO.getId()) {
			throw new DataIntegrityViolationException("CPF Já Cadastrado!");
		}

		tecnico = pessoaRepository.findByEmail(tecnicoDTO.getEmail());
		if (tecnico.isPresent() && tecnico.get().getId() != tecnicoDTO.getId()) {
			throw new DataIntegrityViolationException("Email Já Cadastrado!");
		}

	}

	public Tecnico update(Integer id, @Valid TecnicoDTO tecnicoDTO) {
		tecnicoDTO.setId(id); // Para garantir que o id informado será o q vai ser atualizado
		Tecnico antigoTecnico = findById(id); // Buscar o tecnico por id, caso não ache, será gerado a exerção pelo
												// metodo findById
		validarCpfEEmail(tecnicoDTO);// Validando o CPF e o Email, caso não seja valido, será gerado a exerção pelo
										// metodo validarCpfEEmail

		antigoTecnico = new Tecnico(tecnicoDTO); // Dando tudo certo, vamos atribuir o tecnicoDTO ao tecnicoPorId
		return tecnicoRepository.save(antigoTecnico); // Salvando/atualizando o antigo Tecnico 

	}

	public void delete(Integer id) {
		Tecnico tecnico = findById(id);
		if(tecnico.getChamados().size() > 0) {
			throw new DataIntegrityViolationException("Técnico não pode ser deletado, existe chamado em seu nome!");
		}
		tecnicoRepository.deleteById(id);
	}

}
