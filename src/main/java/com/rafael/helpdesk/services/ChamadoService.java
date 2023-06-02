package com.rafael.helpdesk.services;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.rafael.helpdesk.domain.model.Chamado;
import com.rafael.helpdesk.dtos.ChamadoDTO;
import com.rafael.helpdesk.repositories.ChamadoRepository;
import com.rafael.helpdesk.services.execptions.DataIntegrityViolationException;
import com.rafael.helpdesk.services.execptions.ObjectNotFoundException;

@Service
public class ChamadoService {

	@Autowired
	private ChamadoRepository chamadoRepository;

	public Chamado findById(Integer id) {
		Optional<Chamado> findById = chamadoRepository.findById(id);

		return findById.orElseThrow(() -> new ObjectNotFoundException("Objeto do ID: " + id + " - Não encontrado!"));

	}

	public List<Chamado> findAll() {
		return chamadoRepository.findAll();
	}

	public Chamado create(ChamadoDTO chamadoDTO) {
		chamadoDTO.setId(null);
		Chamado novoChamado = new Chamado(chamadoDTO);
		return chamadoRepository.save(novoChamado);
	}

	public Chamado update(Integer id, ChamadoDTO chamadoDTO) {
		chamadoDTO.setId(id);
		Chamado chamadoAntigo = findById(id);
		chamadoAntigo = new Chamado(chamadoDTO);
		return chamadoRepository.save(chamadoAntigo);
	}

	public void delete(Integer id) {
		Chamado chamado = findById(id);
		if (chamado.getStatus().getCodigo() != 0) {
			throw new DataIntegrityViolationException(
					"Chamado não pode ser excluido, pois está em andamento ou fechado!");
		}
		chamadoRepository.deleteById(id);

	}

}
