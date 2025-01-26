package com.villysiu.springsecurityrestapi.model;

import jakarta.persistence.*;
import lombok.*;


@Entity
@Table
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
