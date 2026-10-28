-- Which layer of the cascade (L0 rules → L1 kNN → L2 classifier → L3 judge) produced each verdict.
select
    layer,
    decision,
    count(*)                           as verdicts,
    round(avg(score)::numeric, 4)      as avg_score
from {{ ref('stg_verdicts') }}
group by 1, 2
order by layer, verdicts desc
