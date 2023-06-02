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

import com.rafael.helpdesk.domain.model.Tecnico;
import com.rafael.helpdesk.dtos.TecnicoDTO;
import com.rafael.helpdesk.services.TecnicoService;

import jakarta.validation.Valid;

@RestController
@RequestMapping(value = "/tecnicos") // localhost:8080/tecnicos
public class TecnicoResource {

	/*
	 * Classe para relacionar a classe de serviço com as requisições
	 */

	@Autowired
	TecnicoService tecnicoService;

	// ResponseEntity é toda resposta HTTP, podendo controlar qualquer coisa, corpo,
	// cabeçalho, status....
	@GetMapping(value = "/{id}") // Ex: localhost:8080/tecnicos/1 - No caso o @PathVariable é o 1
	public ResponseEntity<TecnicoDTO> findById(@PathVariable Integer id) {
		Tecnico tecnico = tecnicoService.findById(id);
		return ResponseEntity.ok().body(new TecnicoDTO(tecnico)); // Vai retornar o ResponseEntity, quando de o ok(),
																	// vai inserir o findById no body

	}

	// Quando não tem nenhum valor, o que valor é o valor do @RequestMapping que
	// colocamos na classe, para acessar esse metodos basta acessar: //
	// localhost:8080/tecnicos
	@GetMapping
	public ResponseEntity<List<TecnicoDTO>> findAll() {
		List<Tecnico> findAll = tecnicoService.findAll();
		/* CConvertendo a lista de Tecnicos para uma lista de TecnicoDTO */
		List<TecnicoDTO> listaTodosTecnicoDTO = findAll.stream().map(tecnico -> new TecnicoDTO(tecnico))
				.collect(Collectors.toList());

		/*
		 * Adicionar uma listaTodosTecnicoDTO no corpo, quando tiver ok na chamada,
		 * então retornamos ResponseEntity
		 */
		return ResponseEntity.ok().body(listaTodosTecnicoDTO);

	}

	@PreAuthorize("hasAnyRole('ADMIN')")
	@PostMapping
	/*
	 * @RequestBody receber e converter o corpo de uma solicitação HTTP em um objeto
	 * Java, simplificando o processamento de dados enviados pelo cliente em APIs
	 * RESTful.
	 * 
	 * @Valid é para informar que existe validação na classe TecnicoDTO, por exemplo
	 * a anotação @NotNull
	 */
	public ResponseEntity<TecnicoDTO> create(@Valid @RequestBody TecnicoDTO tecnicoDTO) {
		Tecnico novoTecnico = tecnicoService.create(tecnicoDTO);

		/*
		 * O comando ServletUriComponentsBuilder.fromCurrentRequest() obtém informações
		 * da requisição atual. Ao chamar .path("/{id}"), adicionamos um trecho variável
		 * ao caminho da URI atual. Em seguida, .build() combina as informações da
		 * requisição e o trecho variável para construir a URI final. Por fim, .toUri()
		 * converte o objeto em uma URI que representa o link desejado. Resumindo, esse
		 * processo cria uma URI dinâmica com base na requisição atual, útil para gerar
		 * links corretos de recursos criados recentemente em APIs RESTful. Isso permite
		 * que os usuários acessem facilmente os recursos criados.
		 */
		URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(novoTecnico.getId())
				.toUri();

		/*
		 * Retorna uma resposta HTTP com o status 201 (Created) e inclui a URI fornecida
		 * no cabeçalho "Location". Usando para indicar que a criação foi feita,
		 * fornecendo o path. O método build() finaliza a construção da resposta. Em
		 * resumo, esse comando é usado para retornar uma resposta adequada após a
		 * criação de um recurso, incluindo a URI desse recurso para referência futura.
		 */
		return ResponseEntity.created(uri).build();

	}

	@PreAuthorize("hasAnyRole('ADMIN')")
	@PutMapping(value = "/{id}") // Utilizada para atualizar recursos existentes, permitindo a modificação de
									// dados no servidor através de requisições PUT
	public ResponseEntity<TecnicoDTO> update(@PathVariable Integer id, @Valid @RequestBody TecnicoDTO tecnicoDTO) { // o
																													// ID
																													// vem
																													// da
																													// url,
																													// o
																													// @Valid
																													// é
																													// a
																													// validação
																													// do
																													// TecnicoDTO
																													// que
																													// vem
																													// no
																													// corpo
																													// da
																													// requisição
																													// (@RequestBody)
		Tecnico tecnicoAtualizado = tecnicoService.update(id, tecnicoDTO); // Chamando metodo update
		return ResponseEntity.ok().body(new TecnicoDTO(tecnicoAtualizado)); // Retornando no corpo um novo TecnicoDTO,
																			// passando o TecnicoAtualizado como
																			// parametro

	}

	@PreAuthorize("hasAnyRole('ADMIN')")
	@DeleteMapping(value = "/{id}")
	public ResponseEntity<TecnicoDTO> delete(@PathVariable Integer id) {
		tecnicoService.delete(id);
		return ResponseEntity.noContent().build();
	}

}
