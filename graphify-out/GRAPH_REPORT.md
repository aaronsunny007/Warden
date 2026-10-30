# Graph Report - Warden  (2026-10-30)

## Corpus Check
- 216 files · ~86,002 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 30 file(s) not represented in the graph (top: (none) 14, .jsonl 2, .example 2)

## Summary
- 2452 nodes · 4732 edges · 160 communities (141 shown, 19 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 354 edges (avg confidence: 0.89)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Java Backend Entities
- Admin API
- Gateway Package Manifest
- Security Workflow
- Detector Client
- Lab Client
- Victim Agent Simulation
- Python Package and Lab Client
- Control Plane API
- GitHub Action
- Policy Matcher Compiler
- Monorepo Tooling
- MCP Proxy Config
- Policy Store
- L2 Classifier
- Eval Harness and Judge
- Agent Framework Tests
- Python Test Fixtures
- Spring Config
- Corpus Builder
- Approvals and HTTP Detector
- Lab Servers Manifest
- Lab Servers CLI
- Signed Bundles
- Policy IR Manifest
- Dashboard Deps and E2E
- Eval Statistics
- Policy CLI Wrapper
- Policy Schema
- Sanitise-then-Reverify ADRs
- Gateway Inspector
- Validation Gate Campaigns
- Compose Healthchecks
- KV Store
- Policy Compiler
- Dashboard Markup
- Docker Build Args
- OTel Collector
- Gateway E2E Tests
- L1 Memory Index
- Contributing Conventions
- dbt Project
- AgentDojo Adapter
- Release and Project Overview
- Detector Service
- Compose Services
- Base TS Config
- Dashboard TS Config
- Spring Tests
- Policy Test Config
- Defence Memory
- LLM Agent Runner
- Alembic Migrations
- Audit Consumer
- Policy IR and Gate Stages
- Gateway Config
- Dashboard and Coverage Docs
- Blue Team
- Helm Replicas
- Helm Images
- Dashboard Page
- Warden CLI
- Acme Data
- Honest Coverage Gaps and Compose Profiles
- CI Steps
- Compose Dependencies
- Gate Report
- dbt Profiles
- Gate Stages G2-G6
- Dependabot
- CI Jobs
- Lab Servers
- Detection Cascade
- Dashboard API Client
- Four-Layer Cascade ADR
- Environment Variables
- Compose Init Policy
- Ollama Judge
- Changelog Fixes
- MCP Injection Surfaces
- Gateway Warden YAML
- Grafana Env
- Kafka Env
- Grafana Dashboards
- Helm Chart
- Integration Tests
- Stub API Server
- Acme Scenario
- Scenario Tasks
- MCP Attacks
- Compose Build
- Compose Ports
- Prometheus
- Approval State
- L2 Scratch Training
- Self-Improving Loop CLI
- CI Workflow
- Event Sinks
- Compose Entrypoints
- Grafana Datasource
- Helm Postgres
- L2 Training
- Scenario Success Checks
- dbt Sources
- Postgres Env
- Embedder
- Dashboard Layout
- dbt Marts
- Compose Kafka
- Compose Host Ports
- Gateway Build Config
- Lab Build Config
- Policy Build Config
- ONNX Classifier
- Dashboard Scripts
- Exfil Attack Args
- Gateway Policy Config
- Server Config
- Compose Volumes
- Helm Dashboard
- Detector Config
- Gateway TS Config
- Lab TS Config
- Policy TS Config
- Dashboard Dependencies
- Injection Tasks
- Terraform Cost Tripwire
- Helm Values
- Kind Config
- Locked Test Split
- Integration CI Env
- CI Triggers
- Not Found Exception
- Detector Client Config
- Pins Config
- Helm Gateway
- Helm Ingress
- Spring Application
- Prettier Config
- CI Node Job
- Postgres Compose Env
- pnpm Workspace
- Message Fixture
- Admin Config
- Failure Config
- Telemetry Config
- PostCSS Config
- Database URL Env
- Demo Script
- Init Policy Script
- Helm Init Policy Script
- Up Script
- Signing Key
- Acme Maven Module
- Warden Root

## God Nodes (most connected - your core abstractions)
1. `Campaign` - 39 edges
2. `ToolSession` - 27 edges
3. `createGateway()` - 26 edges
4. `Stack` - 25 edges
5. `EventBus` - 22 edges
6. `run_experiment()` - 22 edges
7. `run_agentdojo_experiment()` - 22 edges
8. `get_settings()` - 22 edges
9. `TaintStore` - 21 edges
10. `DefenceMemory` - 21 edges

## Surprising Connections (you probably didn't know these)
- `Detection cascade (python/warden/detector)` --semantically_similar_to--> `Detection cascade L0-L3`  [INFERRED] [semantically similar]
  docs/DESIGN.md → README.md
- `Validation gate thesis (prove harmless before enforce)` --semantically_similar_to--> `8-stage validation gate (G1-G8)`  [INFERRED] [semantically similar]
  docs/DESIGN.md → README.md
- `W-TAINT-003 protected-write step-up` --semantically_similar_to--> `W-TAINT-003 protected-write rule`  [INFERRED] [semantically similar]
  docs/OWASP_MAPPING.md → README.md
- `tamper-note goal 13.9% under B3` --semantically_similar_to--> `tamper-note residual 13.9% ASR`  [INFERRED] [semantically similar]
  docs/results/rq1-simulated.md → README.md
- `Compose lab end-to-end fixes` --references--> `Docker-compose lab stack`  [INFERRED]
  CHANGELOG.md → infra/compose/README.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Detection cascade L0 to L3 pipeline** — docs_design_l0_rules, docs_design_l1_knn, docs_design_l2_classifier, docs_design_l3_llm_judge [EXTRACTED 1.00]
- **Validation gate G1-G8 sequential stages** — docs_design_g1_static, docs_design_g2_benign_replay, docs_design_g3_utility, docs_design_g4_efficacy, docs_design_g5_generalisation, docs_design_g6_cost, docs_design_g7_budget, docs_design_g8_approval [EXTRACTED 1.00]
- **ADR-0013/0014/0015 changes that moved B3 results** — docs_decisions_adr_0013, docs_decisions_adr_0014, docs_decisions_adr_0015, docs_results_rq1_simulated_b3_result [EXTRACTED 0.95]

## Communities (160 total, 19 thin omitted)

### Community 0 - "Java Backend Entities"
Cohesion: 0.05
Nodes (12): DataSeeder, Customer, Payment, Ticket, CustomerRepository, PaymentRepository, TicketRepository, CustomerController (+4 more)

### Community 1 - "Admin API"
Cohesion: 0.08
Nodes (30): AdminDeps, registerAdmin(), tokenOk(), createGateway(), Gateway, GatewayOverrides, main(), GatewayConfig (+22 more)

### Community 2 - "Gateway Package Manifest"
Cohesion: 0.05
Nodes (50): bin, warden-gateway, dependencies, fastify@^5.12.7, ioredis@^5.11.1, @modelcontextprotocol/client@2.4.0, @modelcontextprotocol/node@^2.1.2, @modelcontextprotocol/server@2.4.0 (+42 more)

### Community 3 - "Security Workflow"
Cohesion: 0.05
Nodes (45): concurrency, cancel-in-progress, group, GITHUB_TOKEN, name, runs-on, steps, jobs (+37 more)

### Community 4 - "Detector Client"
Cohesion: 0.09
Nodes (23): buildSinks(), DetectorResult, DetectRequest, LayerScore, scoresOf(), UNAVAILABLE, EventSink, JsonlSink (+15 more)

### Community 5 - "Lab Client"
Cohesion: 0.11
Nodes (10): LabClient, Case, run_case(), Stack, LoopResult, LoopRunner, RoundRecord, _dedupe_by_id() (+2 more)

### Community 6 - "Victim Agent Simulation"
Cohesion: 0.11
Nodes (16): AttackSpec, draw(), Episode, SimulatedAgent, sub(), run_simulated(), BenignTask, InjectionTask (+8 more)

### Community 7 - "Python Package and Lab Client"
Cohesion: 0.11
Nodes (11): Budgets, _Window, GateThresholds, campaign_signature(), _campaign(), test_blue_proposes_compilable_rule_and_memory_reuse(), test_budget_caps_rules(), test_gate_blocks_benign_overblocker_at_g2() (+3 more)

### Community 8 - "Control Plane API"
Cohesion: 0.09
Nodes (13): ApproveRequest, create_app(), Base, BenignCall, Campaign, Candidate, CorpusItem, Defence (+5 more)

### Community 9 - "GitHub Action"
Cohesion: 0.06
Nodes (34): author, branding, color, icon, default, description, required, description (+26 more)

### Community 10 - "Policy Matcher Compiler"
Cohesion: 0.13
Nodes (28): compileLeaf(), expandV6(), extractEmails(), extractUrls(), FoundUrl, hostMatches(), INTERNAL_HOSTS, INTERNAL_SUFFIXES (+20 more)

### Community 11 - "Monorepo Tooling"
Cohesion: 0.07
Nodes (32): author, description, devDependencies, eslint@^10.13.0, @eslint/js@^10.0.1, prettier@^3.6.2, @types/node@^22.20.5, typescript@~6.0.3 (+24 more)

### Community 12 - "MCP Proxy Config"
Cohesion: 0.11
Nodes (11): ServerConfig, ToolResult, Catalog, errorResult(), globMatch(), classifyRisk(), PinStatus, ToolDefinition (+3 more)

### Community 13 - "Policy Store"
Cohesion: 0.12
Nodes (17): PolicyStore, PolicyStoreOptions, emptyBundle(), LoadedBundle, CompiledRule, CompileIssue, ACTION_PRECEDENCE, canaryBucket() (+9 more)

### Community 14 - "L2 Classifier"
Cohesion: 0.12
Nodes (12): LiteClassifier, features(), _h(), HashingEmbedder, normalize(), cascade(), test_cascade_separates_attacks_and_tool_outputs(), test_hashing_embedder_is_deterministic_and_normalised() (+4 more)

### Community 15 - "Eval Harness and Judge"
Cohesion: 0.11
Nodes (10): check(), _recipients(), build_cases(), load_suite(), Suite, Template, vector_to_target(), RedTeam (+2 more)

### Community 16 - "Agent Framework Tests"
Cohesion: 0.10
Nodes (9): build_graph(), _lc_name(), make_tools(), run_graph_agent(), agent(), ToolSpec, FakeTools, test_graph_agent_drives_tools() (+1 more)

### Community 17 - "Python Test Fixtures"
Cohesion: 0.10
Nodes (9): _corpus_dir(), load(), LockedSplitError, free_port(), Proc, wait_http(), get_settings(), Settings (+1 more)

### Community 18 - "Spring Config"
Cohesion: 0.07
Nodes (28): name, enabled, password, url, username, health, web, include (+20 more)

### Community 19 - "Corpus Builder"
Cohesion: 0.13
Nodes (17): build_attacks(), build_benign(), dedupe(), fill(), main(), apply_operators(), op_base64(), op_case() (+9 more)

### Community 20 - "Approvals and HTTP Detector"
Cohesion: 0.15
Nodes (4): HttpDetector, ApprovalStore, KV, PinStore

### Community 21 - "Lab Servers Manifest"
Cohesion: 0.08
Nodes (27): bin, warden-lab, dependencies, fastify@^5.12.7, @modelcontextprotocol/node@^2.1.2, @modelcontextprotocol/server@2.4.0, zod@^4.6.7, description (+19 more)

### Community 22 - "Lab Servers CLI"
Cohesion: 0.14
Nodes (19): main(), createLabApp(), ACME_SERVERS, FACTORIES, MALICIOUS_SERVERS, ServerFactory, applyInjections(), cloneWorld() (+11 more)

### Community 23 - "Signed Bundles"
Cohesion: 0.15
Nodes (21): approvalCovers(), generateSigningKey(), KeyPairPem, loadBundle(), LoadResult, signBundle(), signingPayload(), STAGE_RANK (+13 more)

### Community 24 - "Policy IR Manifest"
Cohesion: 0.09
Nodes (25): bin, warden-policy, dependencies, safe-regex2@^5.1.2, zod@^4.6.7, description, devDependencies, fast-check@^4.10.2 (+17 more)

### Community 25 - "Dashboard Deps and E2E"
Cohesion: 0.11
Nodes (22): description, devDependencies, @playwright/test@^1.64.1, postcss@^8.5.6, tailwindcss@^4.3.3, @tailwindcss/postcss@^4.3.3, @types/node@^22.20.5, @types/react@^19.2.2 (+14 more)

### Community 26 - "Eval Statistics"
Cohesion: 0.13
Nodes (11): bootstrap_ci(), cohen_kappa(), McNemar, mcnemar_exact(), Rate, wilson(), test_bootstrap_brackets_p95(), test_kappa() (+3 more)

### Community 27 - "Policy CLI Wrapper"
Cohesion: 0.22
Nodes (13): approve(), _sign_bundle(), build_bundle(), cli_path(), hashes(), keygen(), lint(), PolicyCliError (+5 more)

### Community 28 - "Policy Schema"
Cohesion: 0.08
Nodes (24): Action, ACTIONS, DecodedLeaf, DetectorLeaf, EmailLeaf, FieldRef, HiddenUnicodeLeaf, HostPattern (+16 more)

### Community 29 - "Sanitise-then-Reverify ADRs"
Cohesion: 0.12
Nodes (20): Gateway sanitise-then-reverify (changelog), Split-payload attack (benign-looking address plus injection), W-OUT-006 cascade-confident block, W-OUT-007 cascade-suspicious taint_session, W-OUT-001..007 output rules, 8 attack templates (important_instructions, ignore_previous, ...), B3 after: 3.0% ASR, 96.7% utility under attack, B3 before: 4.5% ASR, 86.5% utility under attack (+12 more)

### Community 30 - "Gateway Inspector"
Cohesion: 0.18
Nodes (7): deepReplace(), Inspector, looksStructured(), redactResult(), resultText(), splitUnits(), TaintStore

### Community 31 - "Validation Gate Campaigns"
Cohesion: 0.21
Nodes (5): Campaign, message_from_campaign(), StageResult, UtilityProbe, ValidationGate

### Community 32 - "Compose Healthchecks"
Cohesion: 0.16
Nodes (23): healthcheck, healthcheck, healthcheck, interval, retries, test, timeout, healthcheck (+15 more)

### Community 33 - "KV Store"
Cohesion: 0.12
Nodes (4): createKV(), FileKV, MemoryKV, RedisKV

### Community 34 - "Policy Compiler"
Cohesion: 0.12
Nodes (22): collectStrings(), compileMatcher(), compilePredicate(), CompileResult, compileRule(), descendants(), Evidence, globToRegex() (+14 more)

### Community 35 - "Dashboard Markup"
Cohesion: 0.09
Nodes (22): p, text, p, text, p, text, p, text (+14 more)

### Community 36 - "Docker Build Args"
Cohesion: 0.13
Nodes (22): NODE_IMAGE, PYTHON_IMAGE, build, args, context, dockerfile, build, build (+14 more)

### Community 37 - "OTel Collector"
Cohesion: 0.09
Nodes (21): verbosity, exporters, debug, prometheus, endpoint, level, protocols, traces (+13 more)

### Community 38 - "Gateway E2E Tests"
Cohesion: 0.13
Nodes (7): baselineRules(), Harness, ROOT, signedBundle(), startHarness(), textOf(), LabApp

### Community 39 - "L1 Memory Index"
Cohesion: 0.13
Nodes (6): MemoryIndex, Neighbour, PgVectorIndex, VectorIndex, build_cascade(), lifespan()

### Community 40 - "Contributing Conventions"
Cohesion: 0.10
Nodes (19): Enforcement needs human approval (G8) convention, Contributing guide, Red-team the lab only convention, Never commit secrets convention, Pre-push CI-equivalent checks, Protected assets, Lab-only, synthetic data, no live targeting, Explicitly out-of-scope threats (+11 more)

### Community 41 - "dbt Project"
Cohesion: 0.10
Nodes (20): analysis-paths, clean-targets, config-version, macro-paths, +materialized, +schema, model-paths, models (+12 more)

### Community 43 - "Release and Project Overview"
Cohesion: 0.13
Nodes (20): CI/CD (GitHub Actions, gitleaks, Semgrep, Trivy, Policy Check Action), Evaluation harness (B0-B4, AgentDojo, statistics), @warden/gateway package, @warden/lab-servers package, Release 0.1.0, Warden analytics (dbt-core), dbt mart asr_by_round (RQ3), dbt mart detection_layer_mix (+12 more)

### Community 44 - "Detector Service"
Cohesion: 0.16
Nodes (10): Example, CorpusAdd, create_app(), add_corpus(), cas(), detect(), info(), DetectRequest (+2 more)

### Community 45 - "Compose Services"
Cohesion: 0.10
Nodes (19): build, image, ports, profiles, restart, name, command, image (+11 more)

### Community 46 - "Base TS Config"
Cohesion: 0.10
Nodes (19): compilerOptions, declaration, esModuleInterop, exactOptionalPropertyTypes, forceConsistentCasingInFileNames, isolatedModules, lib, module (+11 more)

### Community 47 - "Dashboard TS Config"
Cohesion: 0.11
Nodes (18): compilerOptions, allowJs, esModuleInterop, incremental, isolatedModules, jsx, lib, module (+10 more)

### Community 49 - "Policy Test Config"
Cohesion: 0.15
Nodes (13): checkRegex(), LeafInput, PredicateInput, RuleInput, argsCtx(), ctx(), rule(), asOutputRule() (+5 more)

### Community 50 - "Defence Memory"
Cohesion: 0.18
Nodes (4): DefenceMemory, DefenceRecord, PgDefenceMemory, test_memory_reuse_and_retire()

### Community 51 - "LLM Agent Runner"
Cohesion: 0.25
Nodes (12): ollama_model(), build_dojo_cases(), DojoCase, judge_case(), _count(), hypothesis_check(), _rate(), render_markdown() (+4 more)

### Community 52 - "Alembic Migrations"
Cohesion: 0.16
Nodes (6): run_migrations_offline(), run_migrations_online(), url(), upgrade(), _ask(), propose_rule_via_llm()

### Community 53 - "Audit Consumer"
Cohesion: 0.18
Nodes (6): consume(), to_row(), write_batch(), engine(), session_factory(), test_postgres_schema_audit_and_pgvector()

### Community 54 - "Policy IR and Gate Stages"
Cohesion: 0.14
Nodes (14): @warden/policy-ir package, Shadow mode (inspect and record, do not block), G1 static, G8 human approval, Policy IR (packages/policy-ir), Rule modes off/shadow/canary/enforce, Ed25519-signed bundles, Trusted compiler with G1 static checks (safe-regex2) (+6 more)

### Community 55 - "Gateway Config"
Cohesion: 0.15
Nodes (11): dropNulls(), HttpTransport, interpolateEnv(), parseConfig(), StdioTransport, ToolGlob, ToolOverride, spotlight() (+3 more)

### Community 56 - "Dashboard and Coverage Docs"
Cohesion: 0.13
Nodes (15): Next.js agent rules block, Same-origin /admin and /control reverse proxy, Warden dashboard (Next.js), Playwright e2e against stub API, dbt mart owasp_coverage, Control plane and approval queue, OWASP Agentic (ASI) Top 10, Baseline ruleset (20 OWASP-tagged rules) (+7 more)

### Community 57 - "Blue Team"
Cohesion: 0.25
Nodes (6): BlueTeam, _next_version(), _owasp_for(), Proposal, _signal_phrases(), test_signal_phrases_skips_stopwords()

### Community 58 - "Helm Replicas"
Cohesion: 0.15
Nodes (16): control, replicas, resources, resources, lab, replicas, resources, cpu (+8 more)

### Community 59 - "Helm Images"
Cohesion: 0.12
Nodes (16): repository, tag, images, dashboard, node, postgres, python, redis (+8 more)

### Community 60 - "Dashboard Page"
Cohesion: 0.24
Nodes (12): dynamic, Page(), btn(), Dashboard(), td, th, Badge(), DECISION_COLOR (+4 more)

### Community 61 - "Warden CLI"
Cohesion: 0.28
Nodes (10): build_parser(), cmd_agentdojo(), cmd_audit(), cmd_control(), cmd_corpus(), cmd_detector(), cmd_eval(), _csv() (+2 more)

### Community 62 - "Acme Data"
Cohesion: 0.23
Nodes (15): amount, body, city, content, customer_id, id, note, path (+7 more)

### Community 63 - "Honest Coverage Gaps and Compose Profiles"
Cohesion: 0.15
Nodes (14): MCP08 verdict event stream as audit log, Overridable base images (WARDEN_NODE_IMAGE, WARDEN_PYTHON_IMAGE), Docker-compose lab stack, Compose profile kafka (KRaft broker, audit-consumer), Compose profile obs (Prometheus, Grafana, OTel), post-install Alembic migration hook Job, Warden Helm chart, Fixed service names (one release per namespace) (+6 more)

### Community 64 - "CI Steps"
Cohesion: 0.21
Nodes (15): steps, steps, steps, steps, name, run, uses, with (+7 more)

### Community 65 - "Compose Dependencies"
Cohesion: 0.14
Nodes (15): depends_on, build, command, condition, depends_on, entrypoint, image, restart (+7 more)

### Community 66 - "Gate Report"
Cohesion: 0.24
Nodes (5): Row, GateReport, LoopConfig, run_loop_experiment(), LoopStore

### Community 67 - "dbt Profiles"
Cohesion: 0.14
Nodes (13): dbname, host, password, port, schema, sslmode, threads, type (+5 more)

### Community 68 - "Gate Stages G2-G6"
Cohesion: 0.18
Nodes (10): G2 benign replay, G3 utility, G4 efficacy, G5 generalisation, G6 cost, G7 budget (AEGIS-style rate limits), RQ2 gate prevents poisoned-defence self-DoS, Adversary: learning-loop attacker (self-DoS) (+2 more)

### Community 69 - "Dependabot"
Cohesion: 0.14
Nodes (13): npm-minor-patch, pip-minor-patch, update-types, update-types, interval, updates, directories, directory (+5 more)

### Community 70 - "CI Jobs"
Cohesion: 0.15
Nodes (14): name, runs-on, run, defaults, name, runs-on, jobs, dashboard-e2e (+6 more)

### Community 71 - "Lab Servers"
Cohesion: 0.35
Nodes (13): audit(), customers(), email(), facts(), files(), json(), now(), payments() (+5 more)

### Community 72 - "Detection Cascade"
Cohesion: 0.31
Nodes (6): band(), Cascade, Detection, LayerScore, Thresholds, Classifier

### Community 73 - "Dashboard API Client"
Cohesion: 0.24
Nodes (10): api, API_BASE, ApprovalRow, CandidateRow, Control, CoverageItem, Decision, Status (+2 more)

### Community 74 - "Four-Layer Cascade ADR"
Cohesion: 0.26
Nodes (11): Detection cascade (python/warden/detector), L0 deterministic rules, L1 embedding kNN (pgvector), L2 classifier (lite-logreg / ONNX / PromptGuard 2), L3 LLM judge (Ollama, uncertainty band only), L3 judge off unless Ollama configured, lite-logreg L2 fallback, ONNX bundle (model.onnx, tokenizer.json, labels.json) (+3 more)

### Community 75 - "Environment Variables"
Cohesion: 0.17
Nodes (13): environment, environment, environment, WARDEN_CASCADE, WARDEN_DATABASE_URL, WARDEN_DETECTOR_URL, WARDEN_INDEX, WARDEN_JUDGE_MODEL (+5 more)

### Community 76 - "Compose Init Policy"
Cohesion: 0.15
Nodes (13): detector, lab, policy-init, condition, command, depends_on, image, ports (+5 more)

### Community 77 - "Ollama Judge"
Cohesion: 0.26
Nodes (7): Budget, fence(), JudgeResult, OllamaJudge, parse_verdict(), test_budget_caps_calls(), test_judge_fence_and_parse()

### Community 78 - "Changelog Fixes"
Cohesion: 0.20
Nodes (10): CI clean-checkout fixes, Compose lab end-to-end fixes, Release 0.1.1, train_l2_scratch.py added, Rule W-TAINT-003 added (20-rule baseline), W-TAINT-003 protected-write step-up, 11 attack goals (exfil-export, tamper-note, ssrf-metadata, ...), tamper-note goal 13.9% under B3 (+2 more)

### Community 79 - "MCP Injection Surfaces"
Cohesion: 0.21
Nodes (10): Gateway (MCP proxy, packages/gateway), Indirect prompt injection via tool outputs, Three MCP injection surfaces (descriptions, arguments, outputs), Rug pull detection (description pinning and re-list), Spotlighting, Tool poisoning / cross-server shadowing, Adversary: indirect prompt injection via content, Adversary: malicious/compromised MCP server (+2 more)

### Community 80 - "Gateway Warden YAML"
Cohesion: 0.17
Nodes (11): allowedHosts, listen, host, port, spotlight, enabled, state, redisUrl (+3 more)

### Community 81 - "Grafana Env"
Cohesion: 0.17
Nodes (12): GF_AUTH_ANONYMOUS_ENABLED, GF_AUTH_ANONYMOUS_ORG_ROLE, GF_SECURITY_ADMIN_PASSWORD, GF_USERS_DEFAULT_THEME, depends_on, environment, image, ports (+4 more)

### Community 82 - "Kafka Env"
Cohesion: 0.17
Nodes (12): KAFKA_ADVERTISED_LISTENERS, KAFKA_AUTO_CREATE_TOPICS_ENABLE, KAFKA_CONTROLLER_LISTENER_NAMES, KAFKA_CONTROLLER_QUORUM_VOTERS, KAFKA_LISTENER_SECURITY_PROTOCOL_MAP, KAFKA_LISTENERS, KAFKA_NODE_ID, KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR (+4 more)

### Community 83 - "Grafana Dashboards"
Cohesion: 0.17
Nodes (11): apiVersion, foldersFromFilesStructure, path, providers, allowUiUpdates, disableDeletion, folder, name (+3 more)

### Community 84 - "Helm Chart"
Cohesion: 0.17
Nodes (11): apiVersion, appVersion, description, home, keywords, maintainers, name, name (+3 more)

### Community 85 - "Integration Tests"
Cohesion: 0.27
Nodes (4): built(), test_agentdojo_banking_through_warden(), test_policy_cli_round_trip(), test_small_experiment_end_to_end()

### Community 86 - "Stub API Server"
Cohesion: 0.20
Nodes (9): api, approvals, coverage, json(), next, routes, status, tools (+1 more)

### Community 87 - "Acme Scenario"
Cohesion: 0.18
Nodes (10): benign_tasks, id, plan, prompt, reads, mcp_compliance_p, tool, servers (+2 more)

### Community 88 - "Scenario Tasks"
Cohesion: 0.18
Nodes (11): id, text, success, amount, customer_id, customer_note_contains, fetch_internal, refund_at_least (+3 more)

### Community 89 - "MCP Attacks"
Cohesion: 0.18
Nodes (11): mcp_attacks, applies_to_tools, id, rugpull, server, success, trigger, slot (+3 more)

### Community 90 - "Compose Build"
Cohesion: 0.18
Nodes (11): build, command, environment, image, restart, environment, NODE_ENV, WARDEN_CONTROL_URL (+3 more)

### Community 91 - "Compose Ports"
Cohesion: 0.18
Nodes (11): condition, build, depends_on, image, ports, restart, depends_on, control (+3 more)

### Community 92 - "Prometheus"
Cohesion: 0.18
Nodes (10): global, evaluation_interval, scrape_interval, component, scrape_configs, job_name, metrics_path, static_configs (+2 more)

### Community 93 - "Approval State"
Cohesion: 0.31
Nodes (8): ApprovalState, argsHash(), StepUpRequest, definitionHash(), canonicalJson(), sha256Hex(), sortValue(), ruleHash()

### Community 94 - "L2 Scratch Training"
Cohesion: 0.25
Nodes (7): _load_dev(), main(), encode(), __init__(), predict(), _metrics(), _train_tokenizer()

### Community 95 - "Self-Improving Loop CLI"
Cohesion: 0.27
Nodes (3): register(), _run_loop(), _run_rq2()

### Community 96 - "CI Workflow"
Cohesion: 0.20
Nodes (9): concurrency, cancel-in-progress, group, env, NODE_VERSION, PNPM_VERSION, name, permissions (+1 more)

### Community 97 - "Event Sinks"
Cohesion: 0.20
Nodes (10): events, jsonl, kafka, postgres, recordMessages, ringSize, brokers, clientId (+2 more)

### Community 98 - "Compose Entrypoints"
Cohesion: 0.20
Nodes (10): command, entrypoint, environment, image, profiles, restart, volumes, WARDEN_ADMIN_TOKEN (+2 more)

### Community 99 - "Grafana Datasource"
Cohesion: 0.20
Nodes (9): apiVersion, datasources, access, editable, isDefault, name, type, uid (+1 more)

### Community 100 - "Helm Postgres"
Cohesion: 0.20
Nodes (10): database, password, username, enabled, size, postgres, auth, enabled (+2 more)

### Community 101 - "L2 Training"
Cohesion: 0.24
Nodes (3): _load_dev(), main(), _metrics()

### Community 102 - "Scenario Success Checks"
Cohesion: 0.22
Nodes (9): success, contains, path, amount, customer_id, answer_contains, file_written, outbox_to (+1 more)

### Community 103 - "dbt Sources"
Cohesion: 0.22
Nodes (8): sources, description, name, schema, tables, description, name, version

### Community 104 - "Postgres Env"
Cohesion: 0.22
Nodes (9): POSTGRES_DB, POSTGRES_PASSWORD, POSTGRES_USER, env, image, options, ports, services (+1 more)

### Community 105 - "Embedder"
Cohesion: 0.25
Nodes (3): Embedder, make_embedder(), SentenceTransformerEmbedder

### Community 106 - "Dashboard Layout"
Cohesion: 0.25
Nodes (4): metadata, config, next@16.4.3, next

### Community 107 - "dbt Marts"
Cohesion: 0.25
Nodes (7): name, tests, models, columns, description, name, version

### Community 108 - "Compose Kafka"
Cohesion: 0.25
Nodes (8): command, depends_on, image, profiles, restart, kafka, condition, audit-consumer

### Community 109 - "Compose Host Ports"
Cohesion: 0.25
Nodes (8): HOST, PORT, build, command, environment, image, restart, lab

### Community 110 - "Gateway Build Config"
Cohesion: 0.25
Nodes (7): compilerOptions, noEmit, outDir, rootDir, extends, include, ../../tsconfig.base.json

### Community 111 - "Lab Build Config"
Cohesion: 0.25
Nodes (7): compilerOptions, noEmit, outDir, rootDir, extends, include, ../../tsconfig.base.json

### Community 112 - "Policy Build Config"
Cohesion: 0.25
Nodes (7): compilerOptions, noEmit, outDir, rootDir, extends, include, ../../tsconfig.base.json

### Community 114 - "Dashboard Scripts"
Cohesion: 0.29
Nodes (7): scripts, build, dev, lint, start, test:e2e, typecheck

### Community 115 - "Exfil Attack Args"
Cohesion: 0.29
Nodes (7): add_bcc, add_cc, exfil_via_arg, arg, read, tool, effect

### Community 116 - "Gateway Policy Config"
Cohesion: 0.29
Nodes (7): policy, allowUnsigned, bundle, requireHumanApproval, trustedKeys, watch, warden-dev

### Community 117 - "Server Config"
Cohesion: 0.29
Nodes (7): servers, name, taintSources, transport, trust, type, url

### Community 118 - "Compose Volumes"
Cohesion: 0.29
Nodes (7): command, image, ports, profiles, restart, volumes, prometheus

### Community 119 - "Helm Dashboard"
Cohesion: 0.33
Nodes (7): dashboard, replicas, resources, service, service, port, type

### Community 120 - "Detector Config"
Cohesion: 0.29
Nodes (7): detector, cascade, index, judgeModel, l2Mode, ollamaUrl, replicas

### Community 121 - "Gateway TS Config"
Cohesion: 0.29
Nodes (6): compilerOptions, noEmit, rootDir, extends, include, ../../tsconfig.base.json

### Community 122 - "Lab TS Config"
Cohesion: 0.29
Nodes (6): compilerOptions, noEmit, rootDir, extends, include, ../../tsconfig.base.json

### Community 123 - "Policy TS Config"
Cohesion: 0.29
Nodes (6): compilerOptions, noEmit, rootDir, extends, include, ../../tsconfig.base.json

### Community 124 - "Dashboard Dependencies"
Cohesion: 0.33
Nodes (6): dependencies, react@19.3.1, react-dom@19.3.1, recharts@^3.10.1, react-dom, recharts

### Community 125 - "Injection Tasks"
Cohesion: 0.33
Nodes (6): injection_tasks, goal, id, steps, trigger, tool

### Community 126 - "Terraform Cost Tripwire"
Cohesion: 0.33
Nodes (5): Monthly AWS Budget ($1 default), Optional CloudWatch billing alarm + SNS, Terraform cost tripwire module, Optional ECR repositories (keep five tags), Verification status table

### Community 127 - "Helm Values"
Cohesion: 0.33
Nodes (5): adminToken, fullnameOverride, imagePullSecrets, nameOverride, pullPolicy

### Community 128 - "Kind Config"
Cohesion: 0.33
Nodes (5): apiVersion, kind, name, nodes, role

### Community 129 - "Locked Test Split"
Cohesion: 0.50
Nodes (3): Locked test splits convention, RQ1 detection accuracy and benign utility, Statistics (Wilson, McNemar, bootstrap, locked test split)

### Community 130 - "Integration CI Env"
Cohesion: 0.40
Nodes (5): WARDEN_TEST_DATABASE_URL, python-integration, env, name, runs-on

### Community 131 - "CI Triggers"
Cohesion: 0.40
Nodes (5): on, pull_request, push, workflow_dispatch, branches

### Community 133 - "Detector Client Config"
Cohesion: 0.40
Nodes (5): detector, cacheTtlSeconds, channels, timeoutMs, url

### Community 134 - "Pins Config"
Cohesion: 0.40
Nodes (5): pins, autoApproveClean, enabled, refreshSeconds, store

### Community 135 - "Helm Gateway"
Cohesion: 0.40
Nodes (5): gateway, otlpEndpoint, replicas, requireHumanApproval, resources

### Community 136 - "Helm Ingress"
Cohesion: 0.40
Nodes (5): ingress, annotations, className, enabled, host

### Community 138 - "Prettier Config"
Cohesion: 0.40
Nodes (4): printWidth, semi, singleQuote, trailingComma

### Community 139 - "CI Node Job"
Cohesion: 0.50
Nodes (4): node, name, runs-on, steps

### Community 140 - "Postgres Compose Env"
Cohesion: 0.50
Nodes (4): POSTGRES_DB, POSTGRES_PASSWORD, POSTGRES_USER, environment

### Community 141 - "pnpm Workspace"
Cohesion: 0.50
Nodes (3): ignoredBuiltDependencies, onlyBuiltDependencies, packages

### Community 143 - "Message Fixture"
Cohesion: 0.67
Nodes (3): p, text, system_message

### Community 144 - "Admin Config"
Cohesion: 0.67
Nodes (3): admin, enabled, token

### Community 145 - "Failure Config"
Cohesion: 0.67
Nodes (3): failure, highRisk, readOnly

### Community 146 - "Telemetry Config"
Cohesion: 0.67
Nodes (3): telemetry, otlpEndpoint, serviceName

## Knowledge Gaps
- **41 isolated node(s):** `../../tsconfig.base.json`, `../../tsconfig.base.json`, `../../tsconfig.base.json`, `../../tsconfig.base.json`, `../../tsconfig.base.json` (+36 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 998 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **19 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `fence()` connect `Ollama Judge` to `Policy Matcher Compiler`?**
  _High betweenness centrality (0.145) - this node is a cross-community bridge._
- **Are the 11 inferred relationships involving `Campaign` (e.g. with `BlueTeam` and `message_from_campaign()`) actually correct?**
  _`Campaign` has 11 INFERRED edges - model-reasoned connections that need verification._
- **What connects `../../tsconfig.base.json`, `../../tsconfig.base.json`, `../../tsconfig.base.json` to the rest of the system?**
  _41 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Java Backend Entities` be split into smaller, more focused modules?**
  _Cohesion score 0.05427905427905428 - nodes in this community are weakly interconnected._
- **Why does `@opentelemetry/api` connect `Gateway Package Manifest` to `Detector Client`?**
  _High betweenness centrality (0.015) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `ToolSession` (e.g. with `make_tools()` and `run_graph_agent()`) actually correct?**
  _`ToolSession` has 7 INFERRED edges - model-reasoned connections that need verification._
- **Should `Admin API` be split into smaller, more focused modules?**
  _Cohesion score 0.07957393483709273 - nodes in this community are weakly interconnected._