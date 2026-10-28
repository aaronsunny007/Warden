-- Verdict volume and median added latency by server, channel and decision.
select
    server,
    channel,
    decision,
    count(*)                                        as verdicts,
    count(*) filter (where tainted)                 as tainted_verdicts,
    round(avg(latency_ms)::numeric, 3)              as avg_latency_ms,
    round((percentile_cont(0.95) within group (order by latency_ms))::numeric, 3) as p95_latency_ms
from {{ ref('stg_verdicts') }}
group by 1, 2, 3
