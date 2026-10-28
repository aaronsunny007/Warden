-- Attack success rate (ASR) per learning-loop round: the headline RQ3 curve.
select
    run_id,
    round,
    count(*)                                               as attempts,
    count(*) filter (where bypass)                         as bypasses,
    round((count(*) filter (where bypass))::numeric
          / nullif(count(*), 0), 4)                        as asr
from {{ ref('stg_campaigns') }}
group by 1, 2
order by run_id, round
