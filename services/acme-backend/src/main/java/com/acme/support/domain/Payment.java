package com.acme.support.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.Instant;

/** A charge or refund. Refunds are stored as negative-amount rows that reference the charge. */
@Entity
@Table(name = "payments")
public class Payment {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  private String customerId;
  private BigDecimal amount;
  private String currency;
  private String description;
  private boolean refund;
  private Instant createdAt;

  protected Payment() {}

  public Payment(String customerId, BigDecimal amount, String currency, String description, boolean refund) {
    this.customerId = customerId;
    this.amount = amount;
    this.currency = currency;
    this.description = description;
    this.refund = refund;
    this.createdAt = Instant.now();
  }

  public Long getId() {
    return id;
  }

  public String getCustomerId() {
    return customerId;
  }

  public BigDecimal getAmount() {
    return amount;
  }

  public String getCurrency() {
    return currency;
  }

  public String getDescription() {
    return description;
  }

  public boolean isRefund() {
    return refund;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }
}
