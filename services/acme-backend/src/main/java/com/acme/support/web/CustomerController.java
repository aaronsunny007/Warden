package com.acme.support.web;

import com.acme.support.domain.Customer;
import com.acme.support.repo.CustomerRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/customers")
public class CustomerController {
  private final CustomerRepository customers;

  public CustomerController(CustomerRepository customers) {
    this.customers = customers;
  }

  @GetMapping("/{id}")
  public Customer get(@PathVariable String id) {
    return customers.findById(id).orElseThrow(() -> new NotFoundException("customer " + id));
  }
}
