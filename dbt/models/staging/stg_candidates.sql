-- Proposed defences and where each ended up in the validation gate.
select
    id          as candidate_id,
    created_at,
    campaign_id,
    author,
    rule_hash,
    status,
    stage,
    report_id
from {{ source('warden', 'candidates') }}
