-- The validation-gate funnel: how proposed defences are distributed across gate stages/outcomes.
select
    status,
    stage,
    author,
    count(*) as candidates
from {{ ref('stg_candidates') }}
group by 1, 2, 3
order by candidates desc
