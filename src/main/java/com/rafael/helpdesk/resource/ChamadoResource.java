package com.rafael.helpdesk.resource;

import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.rafael.helpdesk.domain.model.Chamado;
import com.rafael.helpdesk.dtos.ChamadoDTO;
import com.rafael.helpdesk.services.ChamadoService;

@RestController
@RequestMapping(value = "/chamados")
public class ChamadoResource {

	@Autowired
	private ChamadoService chamadoService;

	@GetMapping(value = "/{id}")
	public ResponseEntity<ChamadoDTO> findById(@PathVariable Integer id) {
		Chamado chamado = chamadoService.findById(id);
		return ResponseEntity.ok().body(new ChamadoDTO(chamado));

	}

	@GetMapping
	public ResponseEntity<List<ChamadoDTO>> findAll() {
		List<Chamado> findAll = chamadoService.findAll();
		List<ChamadoDTO> findAllChamadoDTO = findAll.stream().map(chamado -> new ChamadoDTO(chamado))
				.collect(Collectors.toList());
		return ResponseEntity.ok().body(findAllChamadoDTO);
	}

	@PostMapping
	public ResponseEntity<ChamadoDTO> create(@RequestBody ChamadoDTO chamadoDTO) {
		chamadoDTO.setId(null);
		Chamado novoChamado = chamadoService.create(chamadoDTO);

		URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(novoChamado.getId())
				.toUri();

		return ResponseEntity.created(uri).build();

	}

	@PutMapping(value = "/{id}")
	public ResponseEntity<ChamadoDTO> update(@PathVariable Integer id, @RequestBody ChamadoDTO chamadoDTO) {
		Chamado chamadoAtualizado = chamadoService.update(id, chamadoDTO);
		return ResponseEntity.ok().body(new ChamadoDTO(chamadoAtualizado));
	}

	@DeleteMapping(value = "/{id}")
	public ResponseEntity<ChamadoDTO> delete(@PathVariable Integer id) {
		chamadoService.delete(id);
		return ResponseEntity.noContent().build();
	}
}
