"""Optional chronology-respecting evaluation for REAL labelled incident outcomes.

No breach probability is published from this module. It supplies temporal
holdout metrics and baseline comparisons only, avoiding invented certainty.
Expected CSV: as_of_date,org_id,incident_next_14d and eight numeric dimensions.
Labels must be independently confirmed and fully observed after as_of_date.
"""
from __future__ import annotations
import csv
import datetime as dt
import math
from collections import Counter
from pathlib import Path
from .scoring import DIMENSION_LABELS

FEATURES = tuple(DIMENSION_LABELS)


def sigmoid(x):
    return 1.0 / (1.0 + math.exp(-max(-40,min(40,x))))


def brier_score(probs, outcomes):
    if not probs or len(probs)!=len(outcomes):
        raise ValueError('Mismatched or empty outcomes')
    return sum((p-y)**2 for p,y in zip(probs,outcomes))/len(probs)


def read_labelled_csv(path: Path, horizon_days=14, today: dt.date | None=None):
    today=today or dt.date.today()
    rows=[]
    with path.open(encoding='utf-8-sig',newline='') as fp:
        for line, row in enumerate(csv.DictReader(fp),start=2):
            try:
                # Generated historical snapshots are UNLABELLED until reviewed.
                # A retrospective backfilled row cannot be used for supervised
                # validation: its features may not have been known on as_of_date.
                snapshot_mode=(row.get('snapshot_mode') or '').strip()
                if snapshot_mode and snapshot_mode != 'strict_observed':
                    raise ValueError('Retrospective/non-strict snapshots cannot be used for model validation')
                if snapshot_mode:
                    review=(row.get('label_status') or '').strip().lower()
                    if review not in {'verified', 'independently_verified'}:
                        raise ValueError('Historical outcome requires independent human verification')
                    evidence=(row.get('outcome_evidence_url') or '').strip()
                    if not evidence.startswith('https://'):
                        raise ValueError('Verified outcome requires independent HTTPS evidence URL')
                date=dt.date.fromisoformat(row['as_of_date'])
                if date+dt.timedelta(days=horizon_days)>today:
                    raise ValueError('Outcome observation window has not closed')
                label=int(row['incident_next_14d'])
                if label not in (0,1):
                    raise ValueError('Outcome must be 0 or 1')
                vals=[float(row[f]) for f in FEATURES]
                if any(not math.isfinite(v) or v<0 or v>5 for v in vals):
                    raise ValueError('All features must be on the original 0..5 scale')
                org=(row.get('org_id') or '').strip()
                if not org:
                    raise ValueError('org_id required')
                rows.append((date,org,vals,label))
            except (KeyError,ValueError,TypeError) as exc:
                raise ValueError(f'Bad labelled sample at line {line}: {exc}') from exc
    if len({(r[0],r[1]) for r in rows}) != len(rows):
        raise ValueError('Duplicate organization/date snapshot')
    rows.sort(key=lambda x:(x[0],x[1]))
    return rows


def temporal_holdout_report(rows, min_examples=80, horizon_days=14):
    """Train on past, test on a separate later period with an embargo gap.

    Evaluates classification, not causal risk. Does not emit org forecasts.
    """
    if len(rows)<min_examples:
        return {'status':'insufficient_labels','count':len(rows),
                'reason':f'Require at least {min_examples} fully labelled historical organization/date snapshots.'}
    cutoff=rows[int(len(rows)*.75)][0]
    train=[r for r in rows if r[0] < cutoff-dt.timedelta(days=horizon_days)]
    test=[r for r in rows if r[0]>=cutoff]
    if len(train)<40 or len(test)<15 or any(sum(r[3]==label for r in group)<5
       for group in (train,test) for label in (0,1)):
        return {'status':'insufficient_labels','count':len(rows),
                'reason':'Chronological train/test groups need >=40 / >=15 samples and >=5 of each outcome per group.'}
    # Fit normalization on training data only. No future statistics enter training.
    d=len(FEATURES)
    means=[sum(r[2][i] for r in train)/len(train) for i in range(d)]
    scales=[max(.5,(sum((r[2][i]-means[i])**2 for r in train)/len(train))**.5) for i in range(d)]
    def vector(r):
        return [1.0]+[(r[2][i]-means[i])/scales[i] for i in range(d)]
    weight=[0.0]*(d+1)
    base=sum(r[3] for r in train)/len(train)
    weight[0]=math.log(base/(1-base))
    for iteration in range(800):
        grad=[0.0]*(d+1)
        for row in train:
            x=vector(row)
            error=sigmoid(sum(w*v for w,v in zip(weight,x)))-row[3]
            for j in range(d+1):
                grad[j]+=error*x[j]
        step=.06/(1+iteration/350)
        for j in range(d+1):
            gradient=grad[j]/len(train)+(.06*weight[j] if j else 0.)
            weight[j]-=step*gradient
    preds=[sigmoid(sum(w*v for w,v in zip(weight,vector(row)))) for row in test]
    labels=[r[3] for r in test]
    score=brier_score(preds,labels)
    naive=brier_score([base]*len(test),labels)
    bins=[]
    for start in (0.0,0.2,0.4,0.6,0.8):
        ids=[i for i,p in enumerate(preds) if start<=p<(start+.2 if start<.8 else 1.0001)]
        if ids:
            bins.append({'range':[start,round(start+.2,1)],'n':len(ids),
                         'predicted':round(sum(preds[i] for i in ids)/len(ids),3),
                         'observed':round(sum(labels[i] for i in ids)/len(ids),3)})
    return {'status':'evaluated_not_deployed','train_count':len(train),'test_count':len(test),
      'cutoff':cutoff.isoformat(),'embargo_days':horizon_days,
      'brier':round(score,4),'baseline_brier':round(naive,4),
      'beats_constant_baseline':score<naive,
      'calibration_bins':bins,
      'calibration_error_ece':round(sum((b['n']/len(test))*abs(b['predicted']-b['observed']) for b in bins),4),
      'event_prevalence_train':round(base,4),'event_prevalence_test':round(sum(labels)/len(labels),4),
      'disclaimer':'Evaluation only. No individual future-attack probability, no claimed causal relationships.'}
