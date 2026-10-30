"""Optional supervised TEXT triage. It is not trained to predict compromises.

Training needs analyst-labelled title/summary examples, uses chronological holdout,
excludes near-duplicate story groups across train/test, and prints a baseline.
No training on model-generated / heuristically assigned labels.
"""
from __future__ import annotations
import csv
import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path

ALLOWED = {'context','claim','incident_report','threat_statement','advisory'}


def read_examples(path: Path):
    samples=[]
    with path.open(encoding='utf-8-sig',newline='') as f:
        for n,row in enumerate(csv.DictReader(f),2):
            label=(row.get('label') or '').strip()
            text=((row.get('title') or '')+' '+(row.get('summary') or '')).strip()
            date=(row.get('published_at') or '').strip()[:10]
            if label not in ALLOWED or len(text)<20:
                raise ValueError(f'Line {n}: label must be one of {sorted(ALLOWED)}, title+summary >=20 chars')
            try: dt.date.fromisoformat(date)
            except ValueError as exc: raise ValueError(f'Line {n}: invalid published_at') from exc
            group=(row.get('story_group') or '').strip()
            if not group:
                # Identical texts cannot appear in both sets even if different URLs.
                group=re.sub(r'\W+',' ',text.casefold()).strip()[:150]
            samples.append((date,text,label,group))
    samples.sort(key=lambda r:r[0])
    return samples


def train(path: Path, output: Path, min_samples: int=60) -> dict:
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        from sklearn.metrics import accuracy_score, f1_score
        import joblib
    except ImportError as exc:
        raise RuntimeError('Install optional ML dependencies: python -m pip install -r requirements-ml.txt') from exc
    rows=read_examples(path)
    labels=Counter(r[2] for r in rows)
    if len(rows)<min_samples or len(labels)<2 or min(labels.values())<15:
        return {'status':'not_trained','reason':'Need >=60 analyst-labelled rows and >=15 samples in each of >=2 classes','counts':dict(labels)}
    cutoff=int(len(rows)*.8)
    test=rows[cutoff:]
    held_groups={r[3] for r in test}
    training=[r for r in rows[:cutoff] if r[3] not in held_groups]
    if len(training)<40 or len(test)<12 or len(set(r[2] for r in training))<2:
        return {'status':'not_trained','reason':'Chronological split/group leakage leaves too few examples'}
    def model():
        return make_pipeline(TfidfVectorizer(analyzer='char_wb',ngram_range=(3,5),max_features=25000,
                                            min_df=2,sublinear_tf=True),
                             LogisticRegression(max_iter=700,class_weight='balanced'))
    m=model();m.fit([r[1] for r in training],[r[2] for r in training])
    expected=[r[2] for r in test]
    pred=m.predict([r[1] for r in test]).tolist()
    baseline=Counter(r[2] for r in training).most_common(1)[0][0]
    report={'status':'trained_text_classifier_not_breach_forecast','train_rows':len(training),
            'test_rows':len(test),'classes':dict(labels),'train_end':training[-1][0],
            'test_start':test[0][0],
            'accuracy':round(float(accuracy_score(expected,pred)),3),
            'macro_f1':round(float(f1_score(expected,pred,average='macro',zero_division=0)),3),
            'baseline_accuracy':round(sum(y==baseline for y in expected)/len(expected),3)}
    # Model for deployment retrains on all labelled examples after temporal evaluation.
    final=model();final.fit([r[1] for r in rows],[r[2] for r in rows])
    output.parent.mkdir(parents=True,exist_ok=True)
    joblib.dump({'model':final,'report':report,'format':'threatwatch-v3-text'},output)
    return {**report,'path':str(output)}


def predict(path: Path, text: str) -> dict:
    import joblib
    if not path.is_file():
        return {'status':'not_available','reason':'No local trained model; classifier falls back to rules'}
    # ONLY load models created by this app on this computer. joblib uses pickle.
    bundle=joblib.load(path)
    if bundle.get('format')!='threatwatch-v3-text':
        raise ValueError('Unknown model format')
    m=bundle['model'];probs=m.predict_proba([text[:6000]])[0]
    ranked=sorted(zip(m.classes_,probs),key=lambda x:-x[1])
    return {'status':'predicted_text_label_not_incident_probability',
            'label':str(ranked[0][0]),'confidence':float(ranked[0][1]),
            'alternatives':{str(k):round(float(v),3) for k,v in ranked}}
