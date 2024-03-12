package com.boardend.boardend.payload.response;

public class ApiResponse<T> {

    private String message;
    private T data;
    private String status;

    // Constructors, getters, and setters

    public ApiResponse() {
    }

    public ApiResponse(String message, T data, String status) {
        this.status = status;
        this.message = message;
        this.data = data;
    }

    // Getters and setters

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
