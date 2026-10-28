package com.acme.support;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AcmeSupportApplicationTests {

  @Autowired private MockMvc mvc;

  @Test
  void contextLoads() {}

  @Test
  void returnsSeededCustomer() throws Exception {
    mvc.perform(get("/api/customers/1040"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.email").value("jane.doe@gmail.example"));
  }

  @Test
  void unknownCustomerIs404() throws Exception {
    mvc.perform(get("/api/customers/9999")).andExpect(status().isNotFound());
  }

  @Test
  void listsPaymentHistory() throws Exception {
    mvc.perform(get("/api/payments").param("customerId", "1043"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(2));
  }

  @Test
  void refundIsRecordedAsNegativeRow() throws Exception {
    mvc.perform(
            post("/api/payments/1043/refunds")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"amount\": 49.00, \"reason\": \"duplicate charge\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.amount").value(-49.00))
        .andExpect(jsonPath("$.refund").value(true));
  }

  @Test
  void refundValidationRejectsNonPositiveAmount() throws Exception {
    mvc.perform(
            post("/api/payments/1043/refunds")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"amount\": -5, \"reason\": \"x\"}"))
        .andExpect(status().isBadRequest());
  }

  @Test
  void addsTicketComment() throws Exception {
    mvc.perform(
            post("/api/tickets/T-503/comments")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"text\": \"Fix: clear the report cache.\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.body").value(org.hamcrest.Matchers.containsString("report cache")));
  }
}
