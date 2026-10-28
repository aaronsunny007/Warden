# Acme Support backend

A small Spring Boot 3 (Java 21) service that stands in for the "real" enterprise customer-support
application in the Warden architecture. The Acme Support **MCP servers** (in `packages/lab-servers`)
expose a slice of this kind of backend as agent tools, and **Warden** sits between an AI agent and
those MCP servers, inspecting every tool description, argument and output.

**All data is synthetic. Lab/evaluation use only.**

## What it is

- **Spring Web + Spring Data JPA + H2** (in-memory), **Validation**, and **Actuator** with a
  **Micrometer Prometheus** registry — the same metrics stack as the rest of Warden.
- Seeded with the same synthetic world as `data/lab/world.json` (customers 1040/1043/1047,
  tickets T-501…T-504, a duplicate October charge for 1043).

## Endpoints

| Method | Path                                 | Notes                                        |
| ------ | ------------------------------------ | -------------------------------------------- |
| GET    | `/api/customers/{id}`                | 404 if unknown                               |
| GET    | `/api/tickets?customerId=`           | list (all, or by customer)                   |
| GET    | `/api/tickets/{id}`                  | one ticket                                   |
| POST   | `/api/tickets/{id}/comments`         | append a comment to the ticket body          |
| GET    | `/api/payments?customerId=`          | payment history                              |
| POST   | `/api/payments/{customerId}/refunds` | issue a refund (negative row); validated     |
| GET    | `/actuator/health`, `/actuator/prometheus` | liveness/readiness and metrics         |

The refund endpoint is the archetypal external-effect action Warden gates: it is exactly the kind
of high-risk call the policy blocks or steps up when the agent's session is tainted or the amount
is not traceable to the user's request.

## Run

```bash
mvn spring-boot:run          # http://localhost:8081
mvn test                     # 7 tests (web layer + validation + 404)
docker build -t warden/acme-backend:dev .
```
