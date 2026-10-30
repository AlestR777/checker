"""Transparent Gamma-Poisson statistics for *observed public claims*, NOT attacks.

For a Poisson claim-arrival process with Gamma(shape=a, rate=b) prior and
observed event count k over t monitored days:
    lambda | data ~ Gamma(a+k, b+t)
    P(at least one claim in next h days) = 1-((b+t)/(b+t+h)) ** (a+k).
This assumes stationarity, stable collection and independent events, often false.
Forecast hidden until enough successful observation days and independent sources.
"""
from __future__ import annotations
import datetime as dt
import math
import random
from .normalize import UTC

PRIOR_ALPHA = 0.5
PRIOR_BETA_DAYS = 7.0


def posterior_predictive(events: int, exposure_days: float, horizon_days: int = 14,
                         *, alpha: float=PRIOR_ALPHA, beta_days: float=PRIOR_BETA_DAYS):
    if events < 0 or exposure_days <= 0 or horizon_days <= 0 or alpha <= 0 or beta_days <= 0:
        raise ValueError('Invalid Gamma-Poisson parameters')
    shape, rate = alpha + events, beta_days + exposure_days
    p = -math.expm1(shape * math.log(rate / (rate + horizon_days)))
    # Deterministic Monte Carlo gamma posterior credible interval for lambda;
    # intervals concern claim rate, *not* forecasting individual breaches.
    rng = random.Random(20261029)
    draws = sorted(rng.gammavariate(shape, 1.0/rate) for _ in range(4000))
    low, high = draws[200], draws[3799]
    return {
      'probability_of_observed_claim': round(p, 4),
      'claim_rate_per_30d': round(shape/rate*30, 3),
      'claim_rate_90pct_interval_per_30d': [round(low*30, 3), round(high*30,3)],
      'events': events, 'exposure_days': round(exposure_days,2),
      'horizon_days': horizon_days, 'model': 'Gamma-Poisson; prior alpha=0.5 beta=7d',
      'warning': 'Probability of >=1 new publicly OBSERVED claim, not of successful compromise; uncalibrated exploratory model.'
    }


def monitored_days(con, *, now: dt.datetime | None=None, lookback_days: int=60):
    now = now or dt.datetime.now(UTC)
    start = (now-dt.timedelta(days=lookback_days)).date().isoformat()
    end = now.date().isoformat()
    rows = con.execute('''SELECT date(checked_at) AS day, count(DISTINCT source_group) AS families
      FROM source_checks WHERE status='ok' AND date(checked_at)>=? AND date(checked_at)<=?
      GROUP BY date(checked_at)''',(start,end)).fetchall()
    return len(rows), len({r['day'] for r in rows if r['families']>=2}), rows


def forecast_from_database(con, org_id: str, *, horizon_days=14, lookback_days=60,
                           now: dt.datetime | None=None):
    """Require >=14 separate monitoring days with >=2 independent source families.

    Unobserved events before collector starts cannot be treated as zero events.
    Never expose individual compromise likelihood or probabilities based only on headlines.
    """
    now = now or dt.datetime.now(UTC)
    any_days, good_days, _ = monitored_days(con,now=now,lookback_days=lookback_days)
    if good_days < 14:
        return {'status':'not_estimated','reason':f'Need >=14 monitoring days with >=2 healthy source families; have {good_days}.',
                'observation_days':good_days,'horizon_days':horizon_days}
    # Backfilled articles predating monitored exposure must not count as arrivals.
    first = con.execute("SELECT min(date(checked_at)) AS first_day FROM source_checks WHERE status='ok' AND checked_at<=?", (now.isoformat(),)).fetchone()['first_day']
    start = max((now-dt.timedelta(days=lookback_days)).isoformat(),first+'T00:00:00+00:00')
    end = now.isoformat()
    rows = con.execute('''SELECT DISTINCT c.id, c.event_kind FROM clusters c
      JOIN cluster_members cm ON cm.cluster_id=c.id
      JOIN items i ON i.id=cm.item_id
      WHERE c.org_id=? AND i.published_at BETWEEN ? AND ?
      AND i.origin!='synthetic' AND i.review_status!='rejected'
      AND c.event_kind IN ('claim','threat_statement','incident_report')''',(org_id,start,end)).fetchall()
    value = posterior_predictive(len(rows),good_days,horizon_days)
    return {'status':'experimental_claim_model','observation_days':good_days, **value}
