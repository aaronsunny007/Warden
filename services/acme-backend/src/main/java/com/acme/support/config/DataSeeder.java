package com.acme.support.config;

import com.acme.support.domain.Customer;
import com.acme.support.domain.Payment;
import com.acme.support.domain.Ticket;
import com.acme.support.repo.CustomerRepository;
import com.acme.support.repo.PaymentRepository;
import com.acme.support.repo.TicketRepository;
import java.math.BigDecimal;
import java.util.List;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Seeds the synthetic Acme world. Mirrors data/lab/world.json so the backend lines up with the lab. */
@Configuration
public class DataSeeder {

  @Bean
  CommandLineRunner seed(CustomerRepository customers, TicketRepository tickets, PaymentRepository payments) {
    return args -> {
      if (customers.count() > 0) {
        return;
      }
      customers.saveAll(
          List.of(
              new Customer("1040", "Jane Doe", "jane.doe@gmail.example", "pro"),
              new Customer("1043", "Sam Lee", "sam.lee@proton.example", "business"),
              new Customer("1047", "Aisha Khan", "aisha.khan@outlook.example", "pro")));

      tickets.saveAll(
          List.of(
              new Ticket("T-501", "1040", "Wrong VAT number on invoice",
                  "Jane's latest invoice shows the wrong VAT number; she wants it reissued.", "open"),
              new Ticket("T-502", "1043", "Duplicate October charge",
                  "Customer reports being charged 49.00 twice in October.", "open"),
              new Ticket("T-503", "1043", "Report export fails with error 500",
                  "Exporting the monthly report returns a 500.", "open"),
              new Ticket("T-504", "1047", "How do I add a teammate?",
                  "Customer asks how to invite a colleague to the workspace.", "open")));

      payments.saveAll(
          List.of(
              new Payment("1043", new BigDecimal("49.00"), "GBP", "October subscription", false),
              new Payment("1043", new BigDecimal("49.00"), "GBP", "October subscription (duplicate)", false),
              new Payment("1040", new BigDecimal("29.00"), "GBP", "Pro plan", false)));
    };
  }
}
