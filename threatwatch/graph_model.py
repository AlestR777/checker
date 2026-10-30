"""Paired, chronological evaluation: direct signals vs direct+graph context.

No per-organization deployment. Requires externally reviewed incident outcomes.
Uses ONLY the strict point-in-time export. The baseline and graph versions use
identical train/test rows and a 14-day time embargo.
"""
from __future__ import annotations
import csv
import datetime as dt
import math
from pathlib import Path
from .calibration import FEATURES, read_labelled_csv, brier_score, sigmoid
from .graph_temporal import GRAPH_FEATURES


def _train_predict(train, test, indices, iterations=700):
    dim=len(indices)
    means=[sum(r[2][i] for r in train)/len(train) for i in indices]
    scales=[max(.5,(sum((r[2][i]-means[j])**2 for r in train)/len(train))**.5)
            for j,i in enumerate(indices)]
    def vector(row): return [1.0]+[(row[2][i]-means[j])/scales[j] for j,i in enumerate(indices)]
    base=sum(r[3] for r in train)/len(train)
    weights=[math.log(base/(1-base))]+[0.]*dim
    for epoch in range(iterations):
        grad=[0.]*(dim+1)
        for r in train:
            x=vector(r)
            error=sigmoid(sum(a*b for a,b in zip(weights,x)))-r[3]
            for i in range(dim+1):grad[i]+=error*x[i]
        step=.06/(1+epoch/350)
        for j in range(dim+1):
            weights[j]-=step*(grad[j]/len(train)+(.06*weights[j] if j else 0.))
    return [sigmoid(sum(a*b for a,b in zip(weights,vector(r)))) for r in test]


def _ece(probs, labels):
    if not probs: return None
    parts=[]
    for lower in (0,.2,.4,.6,.8):
        ids=[i for i,p in enumerate(probs) if lower<=p<(lower+.2 if lower<.8 else 1.001)]
        if ids:
            parts.append({'from':lower,'to':round(lower+.2,1),'count':len(ids),
                          'predicted_mean':round(sum(probs[i] for i in ids)/len(ids),3),
                          'observed_rate':round(sum(labels[i] for i in ids)/len(ids),3)})
    ece=sum((b['count']/len(probs))*abs(b['predicted_mean']-b['observed_rate']) for b in parts)
    return round(ece,4),parts


def validate_graph_history(path:Path, *, today:dt.date|None=None, min_rows=80)->dict:
    # Reuse strict label and evidence checks from the established v3.2 validator.
    labelled=read_labelled_csv(path,today=today)
    with path.open(newline='',encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        required=set(GRAPH_FEATURES)|{'snapshot_mode','label_status','outcome_evidence_url','observed_until'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('Graph validation requires all provenance and graph feature columns: '+', '.join(sorted(required)))
        by_key={}
        for n,r in enumerate(reader,start=2):
            date=dt.date.fromisoformat(r['as_of_date']);org=r['org_id']
            if (r.get('snapshot_mode') or '').strip()!='strict_observed':
                raise ValueError(f'Line {n}: graph model requires strict_observed snapshots')
            try: observed_until=dt.date.fromisoformat(r['observed_until'])
            except (ValueError,TypeError) as exc:
                raise ValueError(f'Line {n}: observed_until date is required') from exc
            if observed_until < date+dt.timedelta(days=14):
                raise ValueError(f'Line {n}: the 14-day outcome must be fully observed')
            vals=[]
            for name in GRAPH_FEATURES:
                try: val=float(r[name])
                except (ValueError,TypeError) as exc:
                    raise ValueError(f'Invalid {name} at line {n}') from exc
                if not math.isfinite(val) or not 0<=val<=5:
                    raise ValueError(f'Graph feature {name} outside 0..5 at line {n}')
                vals.append(val)
            by_key[(date,org)]=vals
    rows=[(date,org,values+by_key[(date,org)],label) for date,org,values,label in labelled]
    if len(rows)<min_rows:
        return {'status':'insufficient_labels','count':len(rows),
                'reason':f'Need at least {min_rows} independently verified snapshots before evaluation.'}
    unique_dates=sorted({r[0] for r in rows})
    if len(unique_dates)<6:
        return {'status':'insufficient_temporal_diversity','dates':len(unique_dates),
                'reason':'At least six distinct snapshot dates are needed.'}
    cutoff=unique_dates[int(len(unique_dates)*.75)]
    embargo=dt.timedelta(days=14)
    train=[r for r in rows if r[0]<cutoff-embargo]
    test=[r for r in rows if r[0]>=cutoff]
    if len(train)<40 or len(test)<15 or any(sum(r[3]==label for r in group)<5
       for group in (train,test) for label in (0,1)):
        return {'status':'insufficient_temporal_class_balance','train':len(train),'test':len(test),
                'reason':'Need >=40 train, >=15 test and >=5 positive and negative outcomes in each split; 14-day embargo enforced.'}
    labels=[r[3] for r in test]
    prior=sum(r[3] for r in train)/len(train)
    direct=_train_predict(train,test,list(range(len(FEATURES))))
    graph=_train_predict(train,test,list(range(len(FEATURES)+len(GRAPH_FEATURES))))
    constant=brier_score([prior]*len(test),labels)
    direct_score=brier_score(direct,labels)
    graph_score=brier_score(graph,labels)
    direct_calibration,direct_bins=_ece(direct,labels)
    graph_calibration,graph_bins=_ece(graph,labels)
    def fmt(n):return round(n,5)
    return {'status':'evaluated_not_deployed',
            'train_snapshots':len(train),'test_snapshots':len(test),
            'train_dates':len(set(r[0] for r in train)),'test_dates':len(set(r[0] for r in test)),
            'train_organizations':len(set(r[1] for r in train)),
            'test_organizations':len(set(r[1] for r in test)),
            'test_start':cutoff.isoformat(),'embargo_days':14,
            'train_event_rate':fmt(prior),'test_event_rate':fmt(sum(labels)/len(labels)),
            'constant_baseline_brier':fmt(constant),
            'direct_signals_brier':fmt(direct_score),
            'direct_plus_graph_brier':fmt(graph_score),
            'graph_minus_direct_brier':fmt(graph_score-direct_score),
            'graph_improved_brier':graph_score<direct_score,
            'direct_calibration_error_ece':direct_calibration,
            'graph_calibration_error_ece':graph_calibration,
            'direct_calibration_bins':direct_bins,
            'graph_calibration_bins':graph_bins,
            'feature_names':{'direct':list(FEATURES),'graph':list(GRAPH_FEATURES)},
            'limitations':('Exploratory holdout; sample bias, delayed detection, correlated weeks, '
                 'source coverage and event-label uncertainty remain. A lower Brier score here '
                 'does not establish a calibrated probability for named organizations. '
                 'Graph links are not attack paths; no model is auto-deployed.')}
