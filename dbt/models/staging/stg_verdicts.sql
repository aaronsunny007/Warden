-- One tidy row per gateway verdict, with array columns kept for downstream unnesting.
select
    id            as verdict_id,
    ts            as decided_at,
    session_id,
    server,
    tool,
    channel,
    risk_tier,
    decision,
    layer,
    score,
    tainted,
    latency_ms,
    bundle_id,
    rule_ids,
    owasp
from {{ source('warden', 'verdicts') }}
