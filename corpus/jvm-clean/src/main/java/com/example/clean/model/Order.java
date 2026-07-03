package com.example.clean.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** JPA entity backing the orders table (corpus: jvm-clean). */
@Entity
@Table(name = "app_order")
public class Order {

    @Id
    private Long id;

    @Column(name = "owner_id")
    private Long ownerId;

    @Column(name = "total")
    private String total;

    public Long getId() {
        return id;
    }

    public Long getOwnerId() {
        return ownerId;
    }

    public String getTotal() {
        return total;
    }
}
