package com.rafael.helpdesk.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rafael.helpdesk.domain.model.Tecnico;

public interface TecnicoRepository extends JpaRepository<Tecnico, Integer>{

}
