package com.acme.support.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** A support customer. The id matches the lab world (e.g. "1040"). */
@Entity
@Table(name = "customers")
public class Customer {
  @Id private String id;
  private String name;
  private String email;
  private String plan;

  protected Customer() {}

  public Customer(String id, String name, String email, String plan) {
    this.id = id;
    this.name = name;
    this.email = email;
    this.plan = plan;
  }

  public String getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public String getEmail() {
    return email;
  }

  public String getPlan() {
    return plan;
  }
}
