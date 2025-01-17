package com.boardend.boardend.advice;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.boardend.boardend.exception.DisabledException;
import com.boardend.boardend.exception.TokenRefreshException;
import com.boardend.boardend.exception.UserNotApprovedException;
import com.boardend.boardend.exception.UserNotFoundException;
import io.jsonwebtoken.MalformedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;


@RestControllerAdvice
@Slf4j
public class TokenControllerAdvice {

    @ExceptionHandler(value = TokenRefreshException.class)
    public ResponseEntity<ErrorMessage> handleTokenRefreshException(TokenRefreshException ex) {
        return new ResponseEntity<>(new ErrorMessage(HttpStatus.FORBIDDEN.value(), ex.getMessage()), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(value = Exception.class)
    public ResponseEntity<ErrorMessage> handleTokenRefreshException(Exception ex) {
        ex.printStackTrace();
        return new ResponseEntity<>(new ErrorMessage(HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.toString()), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(value = UserNotFoundException.class)
    public ResponseEntity<ErrorMessage> handleUserNotFoundException(UserNotFoundException ex) {
        ex.printStackTrace();
        return new ResponseEntity<>(new ErrorMessage(HttpStatus.BAD_REQUEST.value(), ex.getMessage()), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(value = UserNotApprovedException.class)
    public ResponseEntity<ErrorMessage> handleUserNotApprovedException(UserNotApprovedException ex) {
        return new ResponseEntity<>(new ErrorMessage(HttpStatus.UNAUTHORIZED.value(), ex.getMessage()), HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(value = DisabledException.class)
    public ResponseEntity<ErrorMessage> handleDisabledException(DisabledException ex) {
        return new ResponseEntity<>(new ErrorMessage(HttpStatus.UNAUTHORIZED.value(), ex.getMessage()), HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(value = AuthenticationException.class)
    public ResponseEntity<ErrorMessage> handleDisabledException(AuthenticationException ex) {
        ex.printStackTrace();
        return new ResponseEntity<>(new ErrorMessage(HttpStatus.BAD_REQUEST.value(), ex.getMessage()), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(value = MalformedJwtException.class)
    public ResponseEntity<ErrorMessage> handleMalformedJwtException(MalformedJwtException ex) {
        ex.printStackTrace();
        return new ResponseEntity<>(new ErrorMessage(HttpStatus.UNAUTHORIZED.value(), ex.getMessage()), HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorMessage> handleMalformedJwtException(MethodArgumentNotValidException ex) {
        Map<String, Object> errorResponse = new HashMap<>();
        List<FieldError> fieldErrors = ex.getBindingResult().getFieldErrors();
        return new ResponseEntity<>(
                new ErrorMessage(HttpStatus.BAD_REQUEST.value(), fieldErrors.get(0).getField() + " " + fieldErrors.get(0).getDefaultMessage()), HttpStatus.BAD_REQUEST);
    }
}