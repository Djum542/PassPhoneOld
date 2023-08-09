package com.gdu.nhom1.shopproject.models;

public class AuthReponse {
    private String email;
    private String accesstoken;

    public AuthReponse(String email, String accesstoken) {
        this.email = email;
        this.accesstoken = accesstoken;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getAccesstoken() {
        return accesstoken;
    }

    public void setAccesstoken(String accesstoken) {
        this.accesstoken = accesstoken;
    }
}
