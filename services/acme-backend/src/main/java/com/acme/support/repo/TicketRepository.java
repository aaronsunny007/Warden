package com.acme.support.repo;

import com.acme.support.domain.Ticket;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TicketRepository extends JpaRepository<Ticket, String> {
  List<Ticket> findByCustomerId(String customerId);
}
