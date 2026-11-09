# Notices

Warden is licensed under the Apache License 2.0 (see `LICENSE`).

## Third-party

Warden depends on open-source software installed from package registries (npm, PyPI, Maven Central);
each retains its own licence. Notable ones: the Model Context Protocol SDKs (MIT), Fastify (MIT),
FastAPI (MIT), SQLAlchemy (MIT), pgvector (PostgreSQL licence), Next.js (MIT), Spring Boot (Apache-2.0),
dbt-core (Apache-2.0), PyTorch (BSD-3), ONNX Runtime (MIT), AgentDojo (MIT, optional benchmark).

## Data

All attack and benign corpora, customer records, tickets and payments in this repository are synthetic,
generated for evaluation. No real personal or employer data is included.

The one exception is `data/heldout/public_deepset_test.jsonl`: the test file of
[deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) (Apache-2.0,
revision `4f61ecb`), 116 real prompts used only as a held-out evaluation split. It is never trained on.

Round 2 adds real public data under `data/heldout/fresh/` (test splits only, built by `data/heldout/build_fresh_splits.py`):
[neuralchemy/Prompt-injection-dataset](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset)
(Apache-2.0, revision `7d70432`) and
[jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification)
(Apache-2.0, revision `2f2ceeb`). The training files of neuralchemy and of deepset/prompt-injections are downloaded at
training time and not redistributed here.

## Safety

Red-team components target only Warden's bundled lab. Do not use them against systems you do not own
or are not authorised to test.
