package com.rafael.helpdesk.services;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.rafael.helpdesk.domain.model.Cliente;
import com.rafael.helpdesk.domain.model.Pessoa;
import com.rafael.helpdesk.dtos.ClienteDTO;
import com.rafael.helpdesk.repositories.ClienteRepository;
import com.rafael.helpdesk.repositories.PessoaRepository;
import com.rafael.helpdesk.services.execptions.DataIntegrityViolationException;
import com.rafael.helpdesk.services.execptions.ObjectNotFoundException;

import javax.validation.Valid;

@Service // permite a implementação de lógica de negócio e regras de processamento de
			// dados
public class ClienteService {

	@Autowired
	ClienteRepository clienteRepository;

	@Autowired
	PessoaRepository pessoaRepository;
	
	@Autowired
	BCryptPasswordEncoder passwordEncoder;

	public Cliente findById(Integer id) {
		Optional<Cliente> cliente = clienteRepository.findById(id);
		return cliente.orElseThrow(() -> new ObjectNotFoundException("Objeto do ID: " + id + " - Não encontrado!"));

	}

	public List<Cliente> findAll() {
		return clienteRepository.findAll();
	}

	public Cliente create(ClienteDTO clienteDTO) {
		clienteDTO.setId(null);
		clienteDTO.setSenha(passwordEncoder.encode(clienteDTO.getSenha()));
		validarCpfEEmail(clienteDTO);

		Cliente novoCliente = new Cliente(clienteDTO);
		return clienteRepository.save(novoCliente);
	}

	public void validarCpfEEmail(ClienteDTO clienteDTO) {
		Optional<Pessoa> cliente = pessoaRepository.findByCpf(clienteDTO.getCpf());

		if (cliente.isPresent() && cliente.get().getId() != clienteDTO.getId()) {
			throw new DataIntegrityViolationException("CPF Já Cadastrado!");
		}

		cliente = pessoaRepository.findByEmail(clienteDTO.getEmail());
		if (cliente.isPresent() && cliente.get().getId() != clienteDTO.getId()) {
			throw new DataIntegrityViolationException("Email Já Cadastrado!");
		}

	}

	public Cliente update(Integer id, @Valid ClienteDTO clienteDTO) {
		clienteDTO.setId(id);
		Cliente clienteAntigo = findById(id);
		validarCpfEEmail(clienteDTO);
		clienteAntigo = new Cliente(clienteDTO);
		return clienteRepository.save(clienteAntigo);

	}

	public void delete(Integer id) {
		Cliente cliente = findById(id);
		if (cliente.getChamados().size() > 0) {
			throw new DataIntegrityViolationException("Cliente não pode ser excluido, existe chamado em seu nome!");
		}
		clienteRepository.deleteById(id);
	}

}
