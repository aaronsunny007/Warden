package com.acme.support.web;

import com.acme.support.domain.Payment;
import com.acme.support.repo.CustomerRepository;
import com.acme.support.repo.PaymentRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.math.BigDecimal;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/payments")
public class PaymentController {
  private final PaymentRepository payments;
  private final CustomerRepository customers;

  public PaymentController(PaymentRepository payments, CustomerRepository customers) {
    this.payments = payments;
    this.customers = customers;
  }

  @GetMapping
  public List<Payment> history(@RequestParam String customerId) {
    return payments.findByCustomerIdOrderByCreatedAtAsc(customerId);
  }

  /**
   * Issue a refund (a negative-amount row). This is the kind of external-effect action the lab
   * treats as high risk: Warden gates it when the session is tainted or the amount is not
   * traceable to the user's request.
   */
  @PostMapping("/{customerId}/refunds")
  public Payment refund(@PathVariable String customerId, @Valid @RequestBody RefundRequest req) {
    if (!customers.existsById(customerId)) {
      throw new NotFoundException("customer " + customerId);
    }
    Payment refund =
        new Payment(customerId, req.amount().negate(), "GBP", "refund: " + req.reason(), true);
    return payments.save(refund);
  }

  public record RefundRequest(@NotNull @Positive BigDecimal amount, @NotBlank String reason) {}
}
