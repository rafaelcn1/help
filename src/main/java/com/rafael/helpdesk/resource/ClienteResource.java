package com.rafael.helpdesk.resource;

import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.rafael.helpdesk.domain.model.Cliente;
import com.rafael.helpdesk.dtos.ClienteDTO;
import com.rafael.helpdesk.services.ClienteService;

import jakarta.validation.Valid;

@RestController // permite que métodos retornem diretamente objetos convertidos em JSON/XML
@RequestMapping(value = "/clientes") // Mapeamento de uma URL para um método específico em uma classe de controle
public class ClienteResource {

	@Autowired
	private ClienteService clienteService;

	@GetMapping(value = "/{id}")
	public ResponseEntity<ClienteDTO> findById(@PathVariable Integer id) {
		Cliente cliente = clienteService.findById(id);
		return ResponseEntity.ok().body(new ClienteDTO(cliente));

	}

	@GetMapping
	public ResponseEntity<List<ClienteDTO>> findAll() {
		List<Cliente> findAll = clienteService.findAll();
		List<ClienteDTO> findAllClienteDTO = findAll.stream().map(cliente -> new ClienteDTO(cliente))
				.collect(Collectors.toList());

		return ResponseEntity.ok().body(findAllClienteDTO);

	}

	@PostMapping
	@PreAuthorize("hasAnyRole('ADMIN')")
	public ResponseEntity<ClienteDTO> create(@Valid @RequestBody ClienteDTO clienteDTO) {
		Cliente novoCliente = clienteService.create(clienteDTO);

		URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(novoCliente.getId())
				.toUri();

		return ResponseEntity.created(uri).build();
	}
	
	@PutMapping(value = "/{id}")
	@PreAuthorize("hasAnyRole('ADMIN')")
	public ResponseEntity<ClienteDTO> update(@PathVariable Integer id, @Valid @RequestBody ClienteDTO clienteDTO){
		Cliente clienteAtualizado = clienteService.update(id, clienteDTO);
		return ResponseEntity.ok().body(new ClienteDTO(clienteAtualizado));
	}
	
	@DeleteMapping(value = "/{id}")
	@PreAuthorize("hasAnyRole('ADMIN')")
	public ResponseEntity<ClienteDTO> delete(@PathVariable Integer id) {
		clienteService.delete(id);
		return ResponseEntity.noContent().build();
	}

}
