# Graph Report - Warden  (2026-10-30)

## Corpus Check
- 216 files · ~86,002 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 30 file(s) not represented in the graph (top: (none) 14, .jsonl 2, .example 2)

## Summary
- 2277 nodes · 4465 edges · 152 communities (134 shown, 18 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 295 edges (avg confidence: 0.89)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Java Backend Entities
- Gateway Package Manifest
- Security Workflow
- Lab MCP Servers
- Lab Client
- GitHub Action
- Monorepo Tooling
- Detector Client
- Policy Matcher Compiler
- Agent Frameworks
- Admin API
- MCP Proxy
- Signed Bundles
- Control Plane API
- Approvals and Decisions
- Policy Compiler
- Spring Config
- Event Bus
- Lab Servers Manifest
- Simulated Victim Agent
- Warden CLI
- Policy CLI Wrapper
- Policy IR Manifest
- Policy Schema
- LLM Agent Runner
- Dashboard Deps and E2E
- Validation Gate Campaigns
- Eval Statistics
- KV Store
- Compose Healthchecks
- Event Sinks
- L2 Training
- Dashboard Markup
- Database Models
- Docker Build Args
- OTel Collector
- Gateway CLI and Config
- Gateway E2E Tests
- Detector Service
- dbt Project
- Community 40
- Community 41
- Community 42
- Community 43
- Community 44
- Community 45
- Community 46
- Community 47
- Community 48
- Community 49
- Community 50
- Community 51
- Community 52
- Community 53
- Community 54
- Community 55
- Community 56
- Community 57
- Community 58
- Community 59
- Community 60
- Community 61
- Community 62
- Community 63
- Community 64
- Community 65
- Community 66
- Community 67
- Community 68
- Community 69
- Community 70
- Community 71
- Community 72
- Community 73
- Community 74
- Community 75
- Community 76
- Community 77
- Community 78
- Community 79
- Community 80
- Community 81
- Community 82
- Community 83
- Community 84
- Community 85
- Community 86
- Community 87
- Community 88
- Community 89
- Community 90
- Community 91
- Community 92
- Community 93
- Community 94
- Community 95
- Community 96
- Community 97
- Community 98
- Community 99
- Community 100
- Community 101
- Community 102
- Community 103
- Community 104
- Community 105
- Community 106
- Community 107
- Community 108
- Community 109
- Community 110
- Community 111
- Community 112
- Community 113
- Community 114
- Community 115
- Community 116
- Community 117
- Community 118
- Community 119
- Community 120
- Community 121
- Community 122
- Community 123
- Community 124
- Community 125
- Community 126
- Community 127
- Community 128
- Community 129
- Community 130
- Community 131
- Community 132
- Community 133
- Community 134
- Community 135
- Community 136
- Community 137
- Community 138
- Community 139
- Community 140
- Community 141
- Community 142
- Community 143
- Community 144
- Community 145
- Community 150
- Community 151

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
- `main()` --calls--> `Classifier`  [INFERRED]
  training/train_l2_scratch.py → python/src/warden/detector/classifier.py
- `main()` --uses--> `LiteClassifier`  [INFERRED]
  training/train_l2_scratch.py → python/src/warden/detector/classifier.py
- `main()` --uses--> `OnnxClassifier`  [INFERRED]
  training/train_l2_scratch.py → python/src/warden/detector/classifier.py
- `_ask()` --indirect_call--> `url()`  [INFERRED]
  python/src/warden/loop/llm.py → python/migrations/env.py
- `create_app()` --uses--> `Campaign`  [INFERRED]
  python/src/warden/control/service.py → python/src/warden/db/models.py

## Import Cycles
- None detected.

## Communities (152 total, 18 thin omitted)

### Community 0 - "Java Backend Entities"
Cohesion: 0.05
Nodes (12): DataSeeder, Customer, Payment, Ticket, CustomerRepository, PaymentRepository, TicketRepository, CustomerController (+4 more)

### Community 1 - "Gateway Package Manifest"
Cohesion: 0.05
Nodes (50): bin, warden-gateway, dependencies, fastify@^5.12.7, ioredis@^5.11.1, @modelcontextprotocol/client@2.4.0, @modelcontextprotocol/node@^2.1.2, @modelcontextprotocol/server@2.4.0 (+42 more)

### Community 2 - "Security Workflow"
Cohesion: 0.05
Nodes (45): concurrency, cancel-in-progress, group, GITHUB_TOKEN, name, runs-on, steps, jobs (+37 more)

### Community 3 - "Lab MCP Servers"
Cohesion: 0.11
Nodes (33): main(), createLabApp(), LabApp, ACME_SERVERS, audit(), customers(), email(), FACTORIES (+25 more)

### Community 4 - "Lab Client"
Cohesion: 0.11
Nodes (8): LabClient, Stack, LoopRunner, run_loop_experiment(), _sign_bundle(), _dedupe_by_id(), GateProbe, RedTeamConfig

### Community 5 - "GitHub Action"
Cohesion: 0.06
Nodes (34): author, branding, color, icon, default, description, required, description (+26 more)

### Community 6 - "Monorepo Tooling"
Cohesion: 0.07
Nodes (32): author, description, devDependencies, eslint@^10.13.0, @eslint/js@^10.0.1, prettier@^3.6.2, @types/node@^22.20.5, typescript@~6.0.3 (+24 more)

### Community 7 - "Detector Client"
Cohesion: 0.12
Nodes (23): DetectorResult, DetectRequest, LayerScore, scoresOf(), UNAVAILABLE, VerdictDecision, ContentBlock, deepReplace() (+15 more)

### Community 8 - "Policy Matcher Compiler"
Cohesion: 0.09
Nodes (25): compileMatcher(), compilePredicate(), compileRule(), globToRegex(), probeContexts(), Approval, BUNDLE_SCHEMA, BundleInput (+17 more)

### Community 9 - "Agent Frameworks"
Cohesion: 0.08
Nodes (9): build_graph(), _lc_name(), make_tools(), draw(), ToolSpec, FakeTools, test_draw_is_deterministic_and_uniformish(), test_graph_agent_drives_tools() (+1 more)

### Community 10 - "Admin API"
Cohesion: 0.15
Nodes (16): AdminDeps, registerAdmin(), tokenOk(), createGateway(), Gateway, GatewayOverrides, GatewayConfig, Detector (+8 more)

### Community 11 - "MCP Proxy"
Cohesion: 0.11
Nodes (23): ServerConfig, resultText(), ToolInfo, CatalogEntry, globMatch(), SessionInfo, SessionResolver, StepUpFn (+15 more)

### Community 12 - "Signed Bundles"
Cohesion: 0.13
Nodes (20): approvalCovers(), KeyPairPem, loadBundle(), LoadedBundle, LoadResult, signBundle(), signingPayload(), STAGE_RANK (+12 more)

### Community 13 - "Control Plane API"
Cohesion: 0.10
Nodes (7): ApproveRequest, create_app(), _signing_key(), engine(), session_factory(), get_settings(), Settings

### Community 14 - "Approvals and Decisions"
Cohesion: 0.14
Nodes (5): HttpDetector, ApprovalStore, argsHash(), KV, PinStore

### Community 15 - "Policy Compiler"
Cohesion: 0.13
Nodes (26): checkRegex(), collectStrings(), compileLeaf(), CompileResult, descendants(), Matcher, NEUTRAL_ARGS, NEUTRAL_TEXT (+18 more)

### Community 16 - "Spring Config"
Cohesion: 0.07
Nodes (28): name, enabled, password, url, username, health, web, include (+20 more)

### Community 17 - "Event Bus"
Cohesion: 0.12
Nodes (5): EventBus, ToolResult, Catalog, errorResult(), UpstreamManager

### Community 18 - "Lab Servers Manifest"
Cohesion: 0.08
Nodes (27): bin, warden-lab, dependencies, fastify@^5.12.7, @modelcontextprotocol/node@^2.1.2, @modelcontextprotocol/server@2.4.0, zod@^4.6.7, description (+19 more)

### Community 19 - "Simulated Victim Agent"
Cohesion: 0.16
Nodes (8): AttackSpec, SimulatedAgent, McpAttack, Step, ToolCall, ToolSession, RedTeam, RoundResult

### Community 20 - "Warden CLI"
Cohesion: 0.14
Nodes (14): build_parser(), cmd_agentdojo(), cmd_audit(), cmd_control(), cmd_corpus(), cmd_detector(), cmd_eval(), _csv() (+6 more)

### Community 21 - "Policy CLI Wrapper"
Cohesion: 0.21
Nodes (12): approve(), build_bundle(), cli_path(), hashes(), keygen(), lint(), PolicyCliError, replay() (+4 more)

### Community 22 - "Policy IR Manifest"
Cohesion: 0.09
Nodes (25): bin, warden-policy, dependencies, safe-regex2@^5.1.2, zod@^4.6.7, description, devDependencies, fast-check@^4.10.2 (+17 more)

### Community 23 - "Policy Schema"
Cohesion: 0.08
Nodes (25): Action, ACTIONS, DecodedLeaf, DetectorLeaf, EmailLeaf, FieldRef, HiddenUnicodeLeaf, HostPattern (+17 more)

### Community 24 - "LLM Agent Runner"
Cohesion: 0.19
Nodes (18): ollama_model(), run_graph_agent(), Episode, build_dojo_cases(), DojoCase, judge_case(), run_simulated(), Case (+10 more)

### Community 25 - "Dashboard Deps and E2E"
Cohesion: 0.11
Nodes (22): description, devDependencies, @playwright/test@^1.64.1, postcss@^8.5.6, tailwindcss@^4.3.3, @tailwindcss/postcss@^4.3.3, @types/node@^22.20.5, @types/react@^19.2.2 (+14 more)

### Community 26 - "Validation Gate Campaigns"
Cohesion: 0.20
Nodes (5): Campaign, message_from_campaign(), StageResult, UtilityProbe, ValidationGate

### Community 27 - "Eval Statistics"
Cohesion: 0.13
Nodes (11): bootstrap_ci(), cohen_kappa(), McNemar, mcnemar_exact(), Rate, wilson(), test_bootstrap_brackets_p95(), test_kappa() (+3 more)

### Community 28 - "KV Store"
Cohesion: 0.12
Nodes (4): createKV(), FileKV, MemoryKV, RedisKV

### Community 29 - "Compose Healthchecks"
Cohesion: 0.16
Nodes (23): healthcheck, healthcheck, healthcheck, interval, retries, test, timeout, healthcheck (+15 more)

### Community 30 - "Event Sinks"
Cohesion: 0.16
Nodes (8): buildSinks(), EventSink, JsonlSink, Listener, KafkaSink, PostgresSink, Verdict, WardenEvent

### Community 31 - "L2 Training"
Cohesion: 0.12
Nodes (10): _load_dev(), main(), _metrics(), _load_dev(), main(), encode(), __init__(), predict() (+2 more)

### Community 32 - "Dashboard Markup"
Cohesion: 0.09
Nodes (22): p, text, p, text, p, text, p, text (+14 more)

### Community 33 - "Database Models"
Cohesion: 0.14
Nodes (9): Base, BenignCall, Campaign, Candidate, CorpusItem, Defence, EvalRun, GateReport (+1 more)

### Community 34 - "Docker Build Args"
Cohesion: 0.13
Nodes (22): NODE_IMAGE, PYTHON_IMAGE, build, args, context, dockerfile, build, build (+14 more)

### Community 35 - "OTel Collector"
Cohesion: 0.09
Nodes (21): verbosity, exporters, debug, prometheus, endpoint, level, protocols, traces (+13 more)

### Community 36 - "Gateway CLI and Config"
Cohesion: 0.13
Nodes (12): main(), dropNulls(), HttpTransport, interpolateEnv(), loadConfig(), parseConfig(), StdioTransport, ToolGlob (+4 more)

### Community 37 - "Gateway E2E Tests"
Cohesion: 0.13
Nodes (7): baselineRules(), Harness, ROOT, signedBundle(), startHarness(), textOf(), generateSigningKey()

### Community 38 - "Detector Service"
Cohesion: 0.15
Nodes (10): Example, CorpusAdd, create_app(), add_corpus(), cas(), detect(), info(), DetectRequest (+2 more)

### Community 39 - "dbt Project"
Cohesion: 0.10
Nodes (20): analysis-paths, clean-targets, config-version, macro-paths, +materialized, +schema, model-paths, models (+12 more)

### Community 40 - "Community 40"
Cohesion: 0.14
Nodes (6): Embedder, features(), make_embedder(), SentenceTransformerEmbedder, normalize(), test_normalize_strips_invisible_and_reveals_tags()

### Community 41 - "Community 41"
Cohesion: 0.16
Nodes (5): GateThresholds, campaign_signature(), LoopResult, RoundRecord, test_signature_groups_variants()

### Community 42 - "Community 42"
Cohesion: 0.10
Nodes (19): build, image, ports, profiles, restart, name, command, image (+11 more)

### Community 43 - "Community 43"
Cohesion: 0.14
Nodes (4): MemoryIndex, Neighbour, PgVectorIndex, VectorIndex

### Community 44 - "Community 44"
Cohesion: 0.10
Nodes (19): compilerOptions, declaration, esModuleInterop, exactOptionalPropertyTypes, forceConsistentCasingInFileNames, isolatedModules, lib, module (+11 more)

### Community 45 - "Community 45"
Cohesion: 0.11
Nodes (18): compilerOptions, allowJs, esModuleInterop, incremental, isolatedModules, jsx, lib, module (+10 more)

### Community 47 - "Community 47"
Cohesion: 0.17
Nodes (15): FoundUrl, SecretType, findSecrets(), luhn(), PATTERNS, SecretHit, decodeFragments(), decodeTagChars() (+7 more)

### Community 48 - "Community 48"
Cohesion: 0.13
Nodes (4): LiteClassifier, OnnxClassifier, _h(), HashingEmbedder

### Community 49 - "Community 49"
Cohesion: 0.18
Nodes (4): DefenceMemory, DefenceRecord, PgDefenceMemory, test_memory_reuse_and_retire()

### Community 50 - "Community 50"
Cohesion: 0.18
Nodes (12): apply_operators(), op_base64(), op_case(), op_fence(), op_homoglyph(), op_identity(), op_lang_prefix(), op_spacing() (+4 more)

### Community 51 - "Community 51"
Cohesion: 0.14
Nodes (4): sub(), parse_json(), unwrap(), test_unwrap_spotlight()

### Community 52 - "Community 52"
Cohesion: 0.24
Nodes (8): band(), Cascade, Detection, LayerScore, Thresholds, Classifier, build_cascade(), lifespan()

### Community 53 - "Community 53"
Cohesion: 0.25
Nodes (6): BlueTeam, _next_version(), _owasp_for(), Proposal, _signal_phrases(), test_signal_phrases_skips_stopwords()

### Community 54 - "Community 54"
Cohesion: 0.15
Nodes (16): control, replicas, resources, resources, lab, replicas, resources, cpu (+8 more)

### Community 55 - "Community 55"
Cohesion: 0.12
Nodes (16): repository, tag, images, dashboard, node, postgres, python, redis (+8 more)

### Community 56 - "Community 56"
Cohesion: 0.21
Nodes (8): build_cases(), BenignTask, InjectionTask, load_suite(), Suite, Template, vector_to_target(), test_suite_and_cases()

### Community 57 - "Community 57"
Cohesion: 0.20
Nodes (8): Budgets, _Window, _campaign(), test_blue_proposes_compilable_rule_and_memory_reuse(), test_budget_caps_rules(), test_gate_blocks_benign_overblocker_at_g2(), test_gate_passes_narrow_rule_through_replay_stages(), test_message_from_campaign_shape()

### Community 58 - "Community 58"
Cohesion: 0.24
Nodes (12): dynamic, Page(), btn(), Dashboard(), td, th, Badge(), DECISION_COLOR (+4 more)

### Community 59 - "Community 59"
Cohesion: 0.23
Nodes (15): amount, body, city, content, customer_id, id, note, path (+7 more)

### Community 60 - "Community 60"
Cohesion: 0.21
Nodes (15): steps, steps, steps, steps, name, run, uses, with (+7 more)

### Community 61 - "Community 61"
Cohesion: 0.14
Nodes (15): depends_on, build, command, condition, depends_on, entrypoint, image, restart (+7 more)

### Community 62 - "Community 62"
Cohesion: 0.27
Nodes (3): SessionState, TaintSource, TaintStore

### Community 64 - "Community 64"
Cohesion: 0.14
Nodes (13): dbname, host, password, port, schema, sslmode, threads, type (+5 more)

### Community 65 - "Community 65"
Cohesion: 0.14
Nodes (13): npm-minor-patch, pip-minor-patch, update-types, update-types, interval, updates, directories, directory (+5 more)

### Community 66 - "Community 66"
Cohesion: 0.15
Nodes (14): name, runs-on, run, defaults, name, runs-on, jobs, dashboard-e2e (+6 more)

### Community 67 - "Community 67"
Cohesion: 0.23
Nodes (5): built(), test_agentdojo_banking_through_warden(), test_control_plane_reads_and_approves(), test_policy_cli_round_trip(), test_small_experiment_end_to_end()

### Community 68 - "Community 68"
Cohesion: 0.24
Nodes (10): api, API_BASE, ApprovalRow, CandidateRow, Control, CoverageItem, Decision, Status (+2 more)

### Community 69 - "Community 69"
Cohesion: 0.17
Nodes (13): environment, environment, environment, WARDEN_CASCADE, WARDEN_DATABASE_URL, WARDEN_DETECTOR_URL, WARDEN_INDEX, WARDEN_JUDGE_MODEL (+5 more)

### Community 70 - "Community 70"
Cohesion: 0.15
Nodes (13): detector, lab, policy-init, condition, command, depends_on, image, ports (+5 more)

### Community 71 - "Community 71"
Cohesion: 0.26
Nodes (7): Budget, fence(), JudgeResult, OllamaJudge, parse_verdict(), test_budget_caps_calls(), test_judge_fence_and_parse()

### Community 72 - "Community 72"
Cohesion: 0.17
Nodes (11): allowedHosts, listen, host, port, spotlight, enabled, state, redisUrl (+3 more)

### Community 73 - "Community 73"
Cohesion: 0.17
Nodes (12): GF_AUTH_ANONYMOUS_ENABLED, GF_AUTH_ANONYMOUS_ORG_ROLE, GF_SECURITY_ADMIN_PASSWORD, GF_USERS_DEFAULT_THEME, depends_on, environment, image, ports (+4 more)

### Community 74 - "Community 74"
Cohesion: 0.17
Nodes (12): KAFKA_ADVERTISED_LISTENERS, KAFKA_AUTO_CREATE_TOPICS_ENABLE, KAFKA_CONTROLLER_LISTENER_NAMES, KAFKA_CONTROLLER_QUORUM_VOTERS, KAFKA_LISTENER_SECURITY_PROTOCOL_MAP, KAFKA_LISTENERS, KAFKA_NODE_ID, KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR (+4 more)

### Community 75 - "Community 75"
Cohesion: 0.17
Nodes (11): apiVersion, foldersFromFilesStructure, path, providers, allowUiUpdates, disableDeletion, folder, name (+3 more)

### Community 76 - "Community 76"
Cohesion: 0.17
Nodes (11): apiVersion, appVersion, description, home, keywords, maintainers, name, name (+3 more)

### Community 77 - "Community 77"
Cohesion: 0.29
Nodes (4): PolicyStore, PolicyStoreOptions, emptyBundle(), CompileIssue

### Community 78 - "Community 78"
Cohesion: 0.25
Nodes (4): run_migrations_offline(), run_migrations_online(), url(), upgrade()

### Community 79 - "Community 79"
Cohesion: 0.20
Nodes (9): api, approvals, coverage, json(), next, routes, status, tools (+1 more)

### Community 80 - "Community 80"
Cohesion: 0.18
Nodes (10): benign_tasks, id, plan, prompt, reads, mcp_compliance_p, tool, servers (+2 more)

### Community 81 - "Community 81"
Cohesion: 0.18
Nodes (11): id, text, success, amount, customer_id, customer_note_contains, fetch_internal, refund_at_least (+3 more)

### Community 82 - "Community 82"
Cohesion: 0.18
Nodes (11): mcp_attacks, applies_to_tools, id, rugpull, server, success, trigger, slot (+3 more)

### Community 83 - "Community 83"
Cohesion: 0.18
Nodes (11): build, command, environment, image, restart, environment, NODE_ENV, WARDEN_CONTROL_URL (+3 more)

### Community 84 - "Community 84"
Cohesion: 0.18
Nodes (11): condition, build, depends_on, image, ports, restart, depends_on, control (+3 more)

### Community 85 - "Community 85"
Cohesion: 0.18
Nodes (10): global, evaluation_interval, scrape_interval, component, scrape_configs, job_name, metrics_path, static_configs (+2 more)

### Community 87 - "Community 87"
Cohesion: 0.33
Nodes (3): GateReport, LoopConfig, LoopStore

### Community 88 - "Community 88"
Cohesion: 0.27
Nodes (4): _corpus_dir(), load(), LockedSplitError, test_test_split_is_locked()

### Community 89 - "Community 89"
Cohesion: 0.20
Nodes (9): concurrency, cancel-in-progress, group, env, NODE_VERSION, PNPM_VERSION, name, permissions (+1 more)

### Community 90 - "Community 90"
Cohesion: 0.20
Nodes (10): events, jsonl, kafka, postgres, recordMessages, ringSize, brokers, clientId (+2 more)

### Community 91 - "Community 91"
Cohesion: 0.20
Nodes (10): command, entrypoint, environment, image, profiles, restart, volumes, WARDEN_ADMIN_TOKEN (+2 more)

### Community 92 - "Community 92"
Cohesion: 0.20
Nodes (9): apiVersion, datasources, access, editable, isDefault, name, type, uid (+1 more)

### Community 93 - "Community 93"
Cohesion: 0.20
Nodes (10): database, password, username, enabled, size, postgres, auth, enabled (+2 more)

### Community 94 - "Community 94"
Cohesion: 0.42
Nodes (5): build_attacks(), build_benign(), dedupe(), fill(), main()

### Community 95 - "Community 95"
Cohesion: 0.22
Nodes (9): success, contains, path, amount, customer_id, answer_contains, file_written, outbox_to (+1 more)

### Community 96 - "Community 96"
Cohesion: 0.22
Nodes (8): sources, description, name, schema, tables, description, name, version

### Community 97 - "Community 97"
Cohesion: 0.36
Nodes (6): cascade(), test_cascade_separates_attacks_and_tool_outputs(), test_hashing_embedder_is_deterministic_and_normalised(), test_l2only_mode(), test_service_detect_and_info(), test_short_text_abstains_to_l2()

### Community 98 - "Community 98"
Cohesion: 0.22
Nodes (9): POSTGRES_DB, POSTGRES_PASSWORD, POSTGRES_USER, env, image, options, ports, services (+1 more)

### Community 99 - "Community 99"
Cohesion: 0.33
Nodes (8): Evidence, ACTION_PRECEDENCE, Decision, EvaluateOptions, RuleMatch, ActionType, Leaf, Mode

### Community 100 - "Community 100"
Cohesion: 0.36
Nodes (5): consume(), to_row(), write_batch(), Verdict, test_postgres_schema_audit_and_pgvector()

### Community 101 - "Community 101"
Cohesion: 0.28
Nodes (3): free_port(), Proc, wait_http()

### Community 102 - "Community 102"
Cohesion: 0.25
Nodes (4): metadata, config, next@16.4.3, next

### Community 103 - "Community 103"
Cohesion: 0.25
Nodes (7): name, tests, models, columns, description, name, version

### Community 104 - "Community 104"
Cohesion: 0.25
Nodes (8): command, depends_on, image, profiles, restart, kafka, condition, audit-consumer

### Community 105 - "Community 105"
Cohesion: 0.25
Nodes (8): HOST, PORT, build, command, environment, image, restart, lab

### Community 106 - "Community 106"
Cohesion: 0.25
Nodes (7): compilerOptions, noEmit, outDir, rootDir, extends, include, ../../tsconfig.base.json

### Community 107 - "Community 107"
Cohesion: 0.25
Nodes (7): compilerOptions, noEmit, outDir, rootDir, extends, include, ../../tsconfig.base.json

### Community 108 - "Community 108"
Cohesion: 0.25
Nodes (7): compilerOptions, noEmit, outDir, rootDir, extends, include, ../../tsconfig.base.json

### Community 109 - "Community 109"
Cohesion: 0.29
Nodes (7): scripts, build, dev, lint, start, test:e2e, typecheck

### Community 110 - "Community 110"
Cohesion: 0.29
Nodes (7): add_bcc, add_cc, exfil_via_arg, arg, read, tool, effect

### Community 112 - "Community 112"
Cohesion: 0.29
Nodes (7): policy, allowUnsigned, bundle, requireHumanApproval, trustedKeys, watch, warden-dev

### Community 113 - "Community 113"
Cohesion: 0.29
Nodes (7): servers, name, taintSources, transport, trust, type, url

### Community 114 - "Community 114"
Cohesion: 0.29
Nodes (7): command, image, ports, profiles, restart, volumes, prometheus

### Community 115 - "Community 115"
Cohesion: 0.33
Nodes (7): dashboard, replicas, resources, service, service, port, type

### Community 116 - "Community 116"
Cohesion: 0.29
Nodes (7): detector, cascade, index, judgeModel, l2Mode, ollamaUrl, replicas

### Community 117 - "Community 117"
Cohesion: 0.29
Nodes (6): compilerOptions, noEmit, rootDir, extends, include, ../../tsconfig.base.json

### Community 118 - "Community 118"
Cohesion: 0.29
Nodes (6): compilerOptions, noEmit, rootDir, extends, include, ../../tsconfig.base.json

### Community 119 - "Community 119"
Cohesion: 0.29
Nodes (6): compilerOptions, noEmit, rootDir, extends, include, ../../tsconfig.base.json

### Community 120 - "Community 120"
Cohesion: 0.33
Nodes (6): dependencies, react@19.3.1, react-dom@19.3.1, recharts@^3.10.1, react-dom, recharts

### Community 121 - "Community 121"
Cohesion: 0.33
Nodes (6): injection_tasks, goal, id, steps, trigger, tool

### Community 122 - "Community 122"
Cohesion: 0.33
Nodes (5): adminToken, fullnameOverride, imagePullSecrets, nameOverride, pullPolicy

### Community 123 - "Community 123"
Cohesion: 0.33
Nodes (5): apiVersion, kind, name, nodes, role

### Community 124 - "Community 124"
Cohesion: 0.40
Nodes (5): WARDEN_TEST_DATABASE_URL, python-integration, env, name, runs-on

### Community 125 - "Community 125"
Cohesion: 0.40
Nodes (5): on, pull_request, push, workflow_dispatch, branches

### Community 127 - "Community 127"
Cohesion: 0.40
Nodes (5): detector, cacheTtlSeconds, channels, timeoutMs, url

### Community 128 - "Community 128"
Cohesion: 0.40
Nodes (5): pins, autoApproveClean, enabled, refreshSeconds, store

### Community 129 - "Community 129"
Cohesion: 0.40
Nodes (5): gateway, otlpEndpoint, replicas, requireHumanApproval, resources

### Community 130 - "Community 130"
Cohesion: 0.40
Nodes (5): ingress, annotations, className, enabled, host

### Community 132 - "Community 132"
Cohesion: 0.40
Nodes (4): printWidth, semi, singleQuote, trailingComma

### Community 133 - "Community 133"
Cohesion: 0.50
Nodes (4): node, name, runs-on, steps

### Community 134 - "Community 134"
Cohesion: 0.50
Nodes (4): POSTGRES_DB, POSTGRES_PASSWORD, POSTGRES_USER, environment

### Community 135 - "Community 135"
Cohesion: 0.50
Nodes (3): ignoredBuiltDependencies, onlyBuiltDependencies, packages

### Community 136 - "Community 136"
Cohesion: 0.67
Nodes (3): p, text, system_message

### Community 137 - "Community 137"
Cohesion: 0.67
Nodes (3): admin, enabled, token

### Community 138 - "Community 138"
Cohesion: 0.67
Nodes (3): failure, highRisk, readOnly

### Community 139 - "Community 139"
Cohesion: 0.67
Nodes (3): telemetry, otlpEndpoint, serviceName

## Knowledge Gaps
- **8 isolated node(s):** `../../tsconfig.base.json`, `../../tsconfig.base.json`, `../../tsconfig.base.json`, `../../tsconfig.base.json`, `../../tsconfig.base.json` (+3 more)
  These have ≤1 connection - possible missing edges. (Counts symbols only; 960 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **18 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `fence()` connect `Community 71` to `Community 47`?**
  _High betweenness centrality (0.164) - this node is a cross-community bridge._
- **Are the 11 inferred relationships involving `Campaign` (e.g. with `BlueTeam` and `message_from_campaign()`) actually correct?**
  _`Campaign` has 11 INFERRED edges - model-reasoned connections that need verification._
- **What connects `../../tsconfig.base.json`, `../../tsconfig.base.json`, `../../tsconfig.base.json` to the rest of the system?**
  _8 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Java Backend Entities` be split into smaller, more focused modules?**
  _Cohesion score 0.05427905427905428 - nodes in this community are weakly interconnected._
- **Why does `vitest` connect `Policy Matcher Compiler` to `Gateway CLI and Config`, `Gateway E2E Tests`, `Monorepo Tooling`, `Community 47`, `Policy Compiler`?**
  _High betweenness centrality (0.016) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `ToolSession` (e.g. with `make_tools()` and `run_graph_agent()`) actually correct?**
  _`ToolSession` has 7 INFERRED edges - model-reasoned connections that need verification._
- **Should `Gateway Package Manifest` be split into smaller, more focused modules?**
  _Cohesion score 0.05176470588235294 - nodes in this community are weakly interconnected._