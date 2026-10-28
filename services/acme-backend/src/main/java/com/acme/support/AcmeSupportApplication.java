package com.acme.support;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Acme Support — a synthetic customer-support backend used by the Warden lab.
 *
 * <p>In the Warden architecture this is the "real" enterprise application: the Acme Support MCP
 * servers expose a slice of it as tools, and Warden sits between an AI agent and those MCP servers,
 * inspecting every description, argument and output. All data here is synthetic.
 */
@SpringBootApplication
public class AcmeSupportApplication {
  public static void main(String[] args) {
    SpringApplication.run(AcmeSupportApplication.class, args);
  }
}
