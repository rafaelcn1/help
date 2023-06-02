package com.rafael.helpdesk.resource.exceptions;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.rafael.helpdesk.services.execptions.DataIntegrityViolationException;
import com.rafael.helpdesk.services.execptions.ObjectNotFoundException;

import jakarta.servlet.http.HttpServletRequest;

@ControllerAdvice
public class ResourceExceptionHandler {

	/* Classe para personalizar a execption! */

	@ExceptionHandler(ObjectNotFoundException.class) // Anotação para dizer que esse metodo é um manipulador de exerção
														// da classe ObjectNotFoundException.class
	public ResponseEntity<StandardError> objectNotFoundException(ObjectNotFoundException ex,
			HttpServletRequest request) {

		/* Motando o corpo da resposta */

		int valorHttpStatus = HttpStatus.NOT_FOUND.value();
		long timestamp = System.currentTimeMillis();
		String error = "Objeto Not Found";
		String message = ex.getMessage();
		String path = request.getRequestURI();

		StandardError standardError = new StandardError(timestamp, valorHttpStatus, error, message, path);

		// Vai retornar o status do ResponseEntity, adicionando no corpo o
		// standardError, quando não for encontrado
		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(standardError);
	}

	@ExceptionHandler(DataIntegrityViolationException.class) // Anotação para dizer que esse metodo é um manipulador de
																// exerção da classe ObjectNotFoundException.class
	public ResponseEntity<StandardError> dataIntegrityViolationException(DataIntegrityViolationException ex,
			HttpServletRequest request) {

		/* Motando o corpo da resposta */

		int valorHttpStatus = HttpStatus.BAD_REQUEST.value();
		long timestamp = System.currentTimeMillis();
		String error = "Objeto Not Found";
		String message = ex.getMessage();
		String path = request.getRequestURI();

		StandardError standardError = new StandardError(timestamp, valorHttpStatus, error, message, path);

		// Vai retornar o status do ResponseEntity, adicionando no corpo o
		// standardError, quando não for encontrado
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(standardError);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<StandardError> validationErros(MethodArgumentNotValidException ex,
			HttpServletRequest request) {
		int valorHttpStatus = HttpStatus.BAD_REQUEST.value();
		long timestamp = System.currentTimeMillis();
		String error = "Validation Erros";
		String menssagem = "Erro na validação de campos obrigatórios!";
		String path = request.getRequestURI();

		ValidationError erros = new ValidationError(timestamp, valorHttpStatus, error, menssagem, path);

		List<FieldError> listaDeErros = ex.getFieldErrors(); //Lista de erros do MethodArgumentNotValidException
		for (FieldError erro : listaDeErros) {
			String field = erro.getField(); // Fiel que deu o erro
			String message = erro.getDefaultMessage(); // A mensagem padrão do fiel que deu o erro
			erros.addErros(field, message); //Adicionando o erro na lista de erro da classe ValidationError
		}
		return ResponseEntity.status(valorHttpStatus).body(erros);
	}

}
