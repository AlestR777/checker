"""Reproducible, human-gold evaluation of incident-first organization extraction.

An automatic candidate isn't a validated victim. Sample both matched and
unmatched articles; a human labels ALL organization names in a reviewed story.
Never use candidate-name suggestions as the ground truth.
"""
from __future__ import annotations

import csv
import json
import random
from pathlib import Path
from .entity_graph import entity_key

FIELDS = ['url_key','url','published_at','source_name','title','summary',
          'predicted_organizations','reviewed','expected_organizations','reviewer_notes']


def _documents(con):
    # An article may be copied from the discovery inbox into items with a
    # revised title; use ONE deterministic record per URL key.
    rows = con.execute('''SELECT url_key,url,published_at,source_name,title,summary,0 AS priority
      FROM discovery UNION ALL SELECT url_key,url,published_at,source_name,title,summary,1 AS priority
      FROM items ORDER BY priority''').fetchall()
    canonical={row['url_key']:row for row in rows}
    predictions = {}
    for row in con.execute('''SELECT e.url_key, c.name FROM candidate_evidence e
        JOIN entity_candidates c ON c.id=e.candidate_id'''):
        predictions.setdefault(row['url_key'], set()).add(row['name'])
    return [(dict(r), sorted(predictions.get(r['url_key'], set()))) for r in canonical.values()]


def export_review_sample(con, output: Path, size=100, seed=42) -> dict:
    """Deterministically sample matched + unmatched articles; NEVER auto-label."""
    if not 1 <= size <= 10000:
        raise ValueError('Sample size must be 1..10000')
    docs = _documents(con)
    rng = random.Random(seed)
    matched = [d for d in docs if d[1]]
    unmatched = [d for d in docs if not d[1]]
    rng.shuffle(matched)
    rng.shuffle(unmatched)
    half = size // 2
    selected = matched[:min(len(matched), half)] + unmatched[:min(len(unmatched), size-half)]
    already = {d[0]['url_key'] for d in selected}
    if len(selected) < size:
        left = [d for d in matched + unmatched if d[0]['url_key'] not in already]
        selected += left[:size-len(selected)]
    rng.shuffle(selected)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, FIELDS)
        w.writeheader()
        for article, predicted in selected:
            w.writerow({**{k:article.get(k,'') for k in FIELDS},
                'predicted_organizations':' | '.join(predicted),
                'reviewed':'', 'expected_organizations':'', 'reviewer_notes':''})
    return {'status':'unlabelled_review_queue','output':str(output),
            'rows':len(selected),'with_predictions':sum(bool(p) for _,p in selected),
            'without_predictions':sum(not p for _,p in selected),
            'total_articles':len(docs),'seed':seed,
            'instructions':'For each reviewed article, enter ALL organizations actually mentioned and set reviewed=yes; use NONE only for no organizations. Do not copy model predictions as gold.'}


def _names(cell: str) -> set[str]:
    return {entity_key(n) for n in cell.split('|') if n.strip() and n.strip().upper() != 'NONE' and entity_key(n)}


def evaluate_review_sample(path: Path, minimum=20) -> dict:
    """Micro precision/recall from frozen predictions vs independently annotated text.

    An unlabelled row is not a negative. Expected names must be COMPLETE for
    each reviewed article, otherwise recall is not measurable.
    """
    counts = {'tp':0,'fp':0,'fn':0,'reviewed_articles':0,'skipped_unreviewed':0,
              'reviewed_with_no_entities':0,'prediction_articles':0}
    errors = []
    keys = set()
    with path.open(newline='',encoding='utf-8-sig') as f:
        r = csv.DictReader(f)
        if not set(FIELDS).issubset(r.fieldnames or []):
            raise ValueError('Missing columns from entity audit template')
        for number, row in enumerate(r,start=2):
            key = (row.get('url_key') or '').strip()
            if not key or key in keys:
                raise ValueError(f'Missing or duplicate url_key at line {number}')
            keys.add(key)
            if (row.get('reviewed') or '').strip().lower() not in {'yes','да','true','1'}:
                counts['skipped_unreviewed']+=1
                continue
            raw_expected = (row.get('expected_organizations') or '').strip()
            if not raw_expected:
                raise ValueError(f'Line {number}: reviewed article needs exhaustive entity list or NONE')
            pred = _names(row.get('predicted_organizations') or '')
            expected = _names(raw_expected)
            counts['tp']+=len(pred & expected)
            counts['fp']+=len(pred-expected)
            counts['fn']+=len(expected-pred)
            counts['reviewed_articles']+=1
            counts['prediction_articles']+=bool(pred)
            counts['reviewed_with_no_entities']+=not bool(expected)
            if pred != expected and len(errors) < 20:
                errors.append({'url_key':key,'false_positives':sorted(pred-expected),
                               'missed_entities':sorted(expected-pred),
                               'url':row.get('url','')})
    tp,fp,fn = counts['tp'],counts['fp'],counts['fn']
    sufficient=counts['reviewed_articles']>=minimum and (tp+fp)>0 and (tp+fn)>0
    return {'status':'measured' if sufficient else 'insufficient_reviewed_examples',
            **counts,'precision':round(tp/(tp+fp),4) if tp+fp else None,
            'recall':round(tp/(tp+fn),4) if tp+fn else None,
            'f1':round(2*tp/(2*tp+fp+fn),4) if 2*tp+fp+fn else None,
            'example_errors':errors,
            'warning':('These are name-extraction metrics on the REVIEWED sample only. '
                       'They do not measure breach prediction or imply a representative sample of all organizations. '
                       'Names require canonical matching by the reviewer; check acronyms and legal entities.')}
