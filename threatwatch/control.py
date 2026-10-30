"""Safe localhost collection controller: no arbitrary shell commands or remote actions."""
from __future__ import annotations
import datetime as dt
import threading
import time
from .store import connect
from .pipeline import run_once

class CollectionController:
    def __init__(self, db_path, interval_hours=6):
        self.db_path=db_path
        self.interval_seconds=interval_hours*3600
        self._lock=threading.RLock()
        self._cancel=threading.Event()
        self._schedule_thread=None
        self._run_thread=None
        self._scheduled=False
        self._generation=0
        self._busy=False
        self._started=None
        self._finished=None
        self._next=None
        self._result=None
        self._error=None
        self._message='Сбор ещё не запускался'

    def status(self):
        with self._lock:
            def iso(ts):
                return dt.datetime.fromtimestamp(ts,dt.timezone.utc).isoformat(timespec='seconds') if ts else None
            return dict(busy=self._busy,scheduled=self._scheduled,
                started=iso(self._started),finished=iso(self._finished),next_run=iso(self._next),
                error=self._error,result=self._result,message=self._message,
                ai_default='off', interval_hours=self.interval_seconds/3600)

    def run_now(self):
        with self._lock:
            if self._busy:
                return False,'Сбор уже идёт; дождись завершения'
            self._busy=True
            self._started=time.time()
            self._error=None
            self._message='Собираем публичные источники — ИИ выключен'
            self._run_thread=threading.Thread(target=self._worker,daemon=True,name='threatwatch-collector')
            self._run_thread.start()
            return True,'Сбор запущен'

    def _worker(self):
        con=None
        try:
            con=connect(self.db_path)
            result=run_once(con,ai=False,local_ai=False,delay=1.25)
            with self._lock:
                self._result=result
                checked=result.get('checked',0)
                failures=result.get('source_failures',0)
                if checked and failures==checked:
                    self._message='Ни один источник не удалось прочитать. Проверьте доступ к сети и раздел «Источники»'
                elif not checked:
                    self._message='Источники не проверялись: проверьте включённые ленты и ограничения частоты запросов'
                else:
                    self._message=f"Сбор завершён: {result.get('inserted',0)} новых привязанных публикаций"
                    if result.get('errors'):
                        self._message+='; есть ошибки — проверьте источники'
        except Exception as exc:
            with self._lock:
                self._error=f'{type(exc).__name__}: {str(exc)[:350]}'
                self._message='Ошибка сбора; интерфейс остаётся доступен'
        finally:
            if con is not None: con.close()
            with self._lock:
                self._finished=time.time()
                self._busy=False

    def schedule(self):
        with self._lock:
            if self._scheduled:
                return False,'Расписание уже включено'
            self._scheduled=True
            self._generation+=1
            generation=self._generation
            self._cancel=threading.Event()
            cancel=self._cancel
            self._next=time.time()+self.interval_seconds
            self._schedule_thread=threading.Thread(target=self._scheduler,args=(generation,cancel),daemon=True,name='threatwatch-scheduler')
            self._schedule_thread.start()
            return True,'Автосбор включён: раз в 6 часов, пока приложение открыто'

    def _scheduler(self,generation,cancel):
        while True:
            with self._lock:
                if not self._scheduled or self._generation!=generation:return
                remaining=max(0,(self._next or time.time())-time.time())
            if cancel.wait(remaining):return
            with self._lock:
                if not self._scheduled or self._generation!=generation:return
            self.run_now()
            with self._lock:
                if self._generation!=generation:return
                self._next=time.time()+self.interval_seconds

    def unschedule(self):
        with self._lock:
            self._scheduled=False
            self._generation+=1
            self._next=None
            self._cancel.set()
            return True,'Расписание выключено; выполняющийся сбор завершится штатно'

    def shutdown(self):
        self.unschedule()
