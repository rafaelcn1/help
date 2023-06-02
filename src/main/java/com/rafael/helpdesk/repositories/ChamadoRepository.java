package com.rafael.helpdesk.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rafael.helpdesk.domain.model.Chamado;

public interface ChamadoRepository extends JpaRepository<Chamado, Integer>{

}
