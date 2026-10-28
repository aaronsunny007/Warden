package com.acme.support.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** A support ticket. Ticket bodies carry outside-supplied content (the injection vector the lab uses). */
@Entity
@Table(name = "tickets")
public class Ticket {
  @Id private String id;
  private String customerId;
  private String subject;

  @Column(length = 4000)
  private String body;

  private String status;

  protected Ticket() {}

  public Ticket(String id, String customerId, String subject, String body, String status) {
    this.id = id;
    this.customerId = customerId;
    this.subject = subject;
    this.body = body;
    this.status = status;
  }

  public String getId() {
    return id;
  }

  public String getCustomerId() {
    return customerId;
  }

  public String getSubject() {
    return subject;
  }

  public String getBody() {
    return body;
  }

  public String getStatus() {
    return status;
  }

  public void setStatus(String status) {
    this.status = status;
  }
}
