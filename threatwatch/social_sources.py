"""Public social metadata. No authentication bypass, private messages, or media downloads.

Mastodon uses the documented public hashtag timeline. Telegram is opt-in and
parses the official public /s/ preview only. A disabled/unavailable preview
should produce an ordinary source error, not a request for credentials.
"""
from __future__ import annotations
from html.parser import HTMLParser
from urllib.parse import urlencode, quote, urlsplit
from .feeds import Article
from .network import fetch_json, fetch_bytes
from .normalize import clean_markup, parse_date


def parse_mastodon(payload, name: str, limit: int = 40) -> list[Article]:
    if not isinstance(payload, list):
        raise ValueError('Expected Mastodon status list')
    result = []
    for post in payload[:max(0, min(limit, 80))]:
        if not isinstance(post, dict) or post.get('visibility') != 'public':
            continue
        url = str(post.get('url') or '')
        if urlsplit(url).scheme != 'https':
            continue
        content = clean_markup(str(post.get('content') or ''))[:2000]
        if post.get('reblog') and isinstance(post['reblog'], dict):
            # Reposts should not count as original independent testimony.
            content = '[REPOST] ' + clean_markup(str(post['reblog'].get('content') or ''))[:1900]
        date = parse_date(post.get('created_at'))
        if content and date:
            author = post.get('account') or {}
            result.append(Article(content[:180], content, url, date,
                                  f'{name} / {str(author.get("acct") or "public")[:80]}',
                                  'mastodon-public-social'))
    return result


def load_mastodon(src: dict) -> list[Article]:
    base = src['instance'].rstrip('/')
    tag = str(src['hashtag']).lstrip('#').strip()
    if not tag or len(tag) > 80 or any(c in tag for c in '/?#'):
        raise ValueError('Invalid public hashtag')
    url = base + '/api/v1/timelines/tag/' + quote(tag) + '?' + urlencode({'limit':min(40,int(src.get('max_items',40)))})
    payload = fetch_json(url, timeout=int(src.get('timeout',20)))
    return parse_mastodon(payload, src['name'], src.get('max_items',40))


class _TelegramPublicParser(HTMLParser):
    """Minimal parser for official public-channel previews; never fetch linked media."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.posts: list[dict] = []
        self.active: dict | None = None
        self.depth = 0
        self.capture_text = 0
        self.capture_date = 0
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        css = a.get('class', '')
        if tag == 'div' and 'tgme_widget_message_wrap' in css.split():
            self.active = {'post':'','text':[], 'date':''}
            self.depth = 1
        elif self.active is not None:
            if tag == 'div':
                self.depth += 1
            if 'data-post' in a:
                self.active['post'] = a['data-post']
            if 'tgme_widget_message_text' in css:
                self.capture_text += 1
            if tag == 'time' and a.get('datetime'):
                self.active['date'] = a['datetime']
            if tag == 'br' and self.capture_text:
                self.active['text'].append(' ')
    def handle_data(self, data):
        if self.active and self.capture_text:
            self.active['text'].append(data)
    def handle_endtag(self, tag):
        if self.active is None:
            return
        if tag == 'div':
            if self.capture_text:
                self.capture_text -= 1
            self.depth -= 1
            if self.depth <= 0:
                self.posts.append(self.active)
                self.active = None
                self.depth = 0
                self.capture_text = 0


def parse_telegram_public(payload: bytes, name: str, channel: str, limit: int = 40) -> list[Article]:
    parser = _TelegramPublicParser()
    parser.feed(payload.decode('utf-8',errors='replace'))
    result=[]
    for post in parser.posts[:max(0,min(limit,100))]:
        post_id = post['post']
        text = clean_markup(' '.join(post['text']))[:2000]
        date = parse_date(post['date'])
        if not text or not date or not post_id.startswith(channel + '/'):
            continue
        result.append(Article(text[:180],text,'https://t.me/'+post_id,date,name,'telegram-public-social'))
    return result


def load_telegram(src: dict) -> list[Article]:
    channel = str(src['channel']).lstrip('@').strip()
    if not channel.replace('_','').isalnum() or not 4 <= len(channel) <= 32:
        raise ValueError('Invalid public Telegram channel identifier')
    url = f'https://t.me/s/{channel}'
    payload = fetch_bytes(url,timeout=int(src.get('timeout',25)),max_bytes=1_000_000,accept='text/html')
    return parse_telegram_public(payload,src['name'],channel,int(src.get('max_items',40)))
