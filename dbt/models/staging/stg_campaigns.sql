-- Red-team attempts. `bypass` marks a confirmed harmful action on lab state.
select
    id          as campaign_id,
    created_at,
    run_id,
    round,
    family,
    goal,
    vector,
    bypass
from {{ source('warden', 'campaigns') }}
