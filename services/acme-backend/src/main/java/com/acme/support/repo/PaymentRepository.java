package com.acme.support.repo;

import com.acme.support.domain.Payment;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PaymentRepository extends JpaRepository<Payment, Long> {
  List<Payment> findByCustomerIdOrderByCreatedAtAsc(String customerId);
}
