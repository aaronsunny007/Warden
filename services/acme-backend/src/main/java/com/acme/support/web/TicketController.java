package com.acme.support.web;

import com.acme.support.domain.Ticket;
import com.acme.support.repo.TicketRepository;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/tickets")
public class TicketController {
  private final TicketRepository tickets;

  public TicketController(TicketRepository tickets) {
    this.tickets = tickets;
  }

  @GetMapping
  public List<Ticket> list(@RequestParam(required = false) String customerId) {
    return customerId == null ? tickets.findAll() : tickets.findByCustomerId(customerId);
  }

  @GetMapping("/{id}")
  public Ticket get(@PathVariable String id) {
    return tickets.findById(id).orElseThrow(() -> new NotFoundException("ticket " + id));
  }

  /** Append a comment to the ticket body, mirroring the lab's tickets.add_comment tool. */
  @PostMapping("/{id}/comments")
  public Ticket addComment(@PathVariable String id, @RequestBody CommentRequest req) {
    Ticket t = tickets.findById(id).orElseThrow(() -> new NotFoundException("ticket " + id));
    Ticket updated =
        new Ticket(t.getId(), t.getCustomerId(), t.getSubject(), t.getBody() + "\n\n[comment] " + req.text(), t.getStatus());
    return tickets.save(updated);
  }

  public record CommentRequest(@NotBlank String text) {}
}
