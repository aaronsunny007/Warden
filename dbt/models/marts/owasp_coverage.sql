-- How often each OWASP category (ASI / MCP) is cited by a non-allow verdict.
with exploded as (
    select
        v.verdict_id,
        v.decision,
        code as owasp_code
    from {{ ref('stg_verdicts') }} v
    cross join lateral unnest(v.owasp) as code
)
select
    owasp_code,
    count(*)                                   as verdicts,
    count(*) filter (where decision <> 'allow') as enforced_or_flagged,
    count(distinct verdict_id)                 as distinct_messages
from exploded
group by 1
order by verdicts desc
