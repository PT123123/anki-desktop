"""同步调度（SPEC-v2 §8）：三档周期 + 三个"不等下一轮"的触发点 + 不可达自愈。

策略全在这里，engine 只提供事实（谁是已配对在线的 peer、谁脏了、上一轮什么时候跑的）。
循环固定 1s 一跳，所以"改档 ≤5s 生效"是结构性成立的：每跳都重读 `engine.interval_secs()`。
"""

from __future__ import annotations

import logging
import threading
import time

from .engine import LanEngine
from .protocol import OFFLINE_AFTER_SECS

log = logging.getLogger("anki.lansync.scheduler")

INTERVAL_PRESETS = (10, 300, 1800)
DEBOUNCE_SECS = 5.0
MIN_ROUND_INTERVAL = 15.0
REPROBE_SECS = 30.0
REDISCOVER_WINDOW = 6.0
HEAL_THROTTLE_SECS = 30.0
TICK_SECS = 1.0


class Scheduler:
    def __init__(self, engine: LanEngine, tick: float = TICK_SECS) -> None:
        self.engine = engine
        self.tick = tick
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_cycle = 0.0
        self._last_reprobe = 0.0
        self._last_heal = 0.0
        self.rounds_run = 0

    def start(self) -> None:
        if self._thread:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="lansync-sched")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.wait(self.tick):
            try:
                self.step()
            except Exception:  # noqa: BLE001 - 调度线程绝不能因为一轮异常而静默死掉
                log.exception("lansync 调度异常")

    # ------------------------------------------------------------- 一步一策
    def step(self) -> dict:
        """公开出来便于测试台架直接驱动，不必依赖真实时间流逝。"""
        now = time.time()
        actions: dict[str, object] = {"reasons": [], "due": [], "healed": False}
        if not self.engine.enabled():
            if self.engine.server is not None:
                # 关掉开关要真的把端口收回：常驻的 serve 走这条路径
                self.engine.stop()
            return actions

        reasons = self.engine.consume_immediate()
        if reasons:
            actions["reasons"] = reasons
            self._run(reasons[0], self.engine.paired_peers())
            self._last_cycle = now
            return actions

        due = [pid for pid in self.engine.due_peers(DEBOUNCE_SECS, MIN_ROUND_INTERVAL)]
        if due:
            actions["due"] = due
            self._run("dirty", [self.engine.peer_state(pid) for pid in due])
            self._last_cycle = now

        interval = self.engine.interval_secs()
        if interval and now - self._last_cycle >= interval:
            actions["reasons"] = ["cycle"]
            self._run("cycle", self.engine.paired_peers())
            self._last_cycle = now

        if now - self._last_reprobe >= REPROBE_SECS:
            self._last_reprobe = now
            self._heal(now)
        return actions

    def _run(self, reason: str, states: list) -> None:
        targets = [s for s in states if s is not None]
        if not targets:
            return
        log.info("lansync round: reason=%s peers=%s", reason,
                 ",".join((s.name or s.peer_id[:8]) for s in targets))
        for state in targets:
            self.rounds_run += 1
            try:
                self.engine.sync_round(state.peer_id)
            except Exception as exc:  # noqa: BLE001 - 一个 peer 失败不该带走整批
                log.warning("与 %s 同步失败: %s", state.peer_id[:8], exc)
        self.engine.clear_dirty([s.peer_id for s in targets])

    def _heal(self, now: float) -> None:
        """离线设备补探；一台都没回来就开一次重发现窗口（刷 IP），自愈本身限流 30s。"""
        if not self.engine.paired_peers(online_only=False):
            return
        known = {s.peer_id: (s.host, s.port, s.last_heard) for s in
                 self.engine.paired_peers(online_only=False)}
        offline = [pid for pid, (_h, _p, heard) in known.items() if not self._fresh(heard)]
        if not offline:
            return
        refreshed = set(self.engine.reprobe_all())
        if refreshed & set(offline) or now - self._last_heal < HEAL_THROTTLE_SECS:
            return
        self._last_heal = now
        if self.engine.discovery:
            self.engine.discovery.kick(REDISCOVER_WINDOW)
        log.info("lansync 自愈：重发现窗口 %ss", REDISCOVER_WINDOW)

    @staticmethod
    def _fresh(heard: float) -> bool:
        return (time.time() - heard) <= OFFLINE_AFTER_SECS
