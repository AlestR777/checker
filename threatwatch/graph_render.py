"""Static one-hop evidence graph; relationship review is visible on every edge."""
from __future__ import annotations
import html
import math
from urllib.parse import quote


def relation_svg(focal_id: str, focal_name: str, relations: list[dict], max_nodes=9, co_mentions=None) -> str:
    seen=set();nodes=[]
    max_nodes=max(0,min(int(max_nodes),30))
    # Prefer verified relationships, then cited suggestions, then co-mentions.
    for status in ('verified','unverified'):
        for r in relations:
            if len(nodes)>=max_nodes: break
            if r.get('review_status')!=status: continue
            oid=r['other_id']
            if not oid or oid==focal_id or oid in seen: continue
            seen.add(oid);nodes.append((oid,r['other_name'],status))
    for r in co_mentions or []:
        if len(nodes)>=max_nodes: break
        oid=r['id']
        if not oid or oid==focal_id or oid in seen: continue
        seen.add(oid);nodes.append((oid,r['name'],'co_mentioned'))
    if not nodes:
        return ('<div class="card"><h2>Пока нет связей для рисунка</h2>'
                '<p>В базе нет документальных отношений и совместных упоминаний с этой организацией. '
                'Это пробел в данных, а не доказательство отсутствия связей. '
                'Связи из явных формулировок публикаций появятся как предложения для проверки; '
                'также можно добавить отношение с публичным источником.</p></div>')
    cx,cy=350,210
    out=['<div class="card"><h2>Схема связей</h2><svg viewBox="0 0 700 440" role="img" aria-label="Связи организации: сплошная фиолетовая — проверенные, янтарный пунктир — предложения, серые точки — совместные упоминания" '
         'style="width:100%;max-height:470px;border-radius:10px;background:#0d0b12">']
    styles={'verified':('#ad85ff',''), 'unverified':('#d4ac79',' stroke-dasharray="8 5"'),
            'co_mentioned':('#7d758f',' stroke-dasharray="2 6"')}
    for idx,(oid,name,kind) in enumerate(nodes):
        angle=2*math.pi*idx/len(nodes)-math.pi/2
        x=cx+240*math.cos(angle);y=cy+145*math.sin(angle)
        color,dash=styles[kind]
        out.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" stroke="{color}" stroke-width="2"{dash}/>')
        out.append(f'<a href="/org/{html.escape(quote(oid,safe=""),quote=True)}"><circle cx="{x:.1f}" cy="{y:.1f}" r="24" fill="#25202f" stroke="{color}" stroke-width="2"/>')
        out.append(f'<text x="{x:.1f}" y="{y+39:.1f}" font-size="12" fill="#e0e0e0" text-anchor="middle">{html.escape(name[:27])}</text></a>')
    out.append(f'<circle cx="{cx}" cy="{cy}" r="36" fill="#503477" stroke="#ad85ff" stroke-width="3"/>')
    out.append(f'<text x="{cx}" y="{cy+55}" text-anchor="middle" font-size="13" fill="#fff">{html.escape(focal_name[:35])}</text>')
    out.append('</svg><p class="muted"><strong style="color:#ad85ff">━</strong> Подтверждённая документальная связь · '
               '<strong style="color:#d4ac79">┄</strong> Предложенная связь, требует проверки · '
               '<strong style="color:#7d758f">···</strong> Совместно упомянуты в публикации (не деловые отношения). '
               'Сходство отрасли и страны в граф не добавляется.</p></div>')
    return ''.join(out)
