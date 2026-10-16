# V22 最小监督资格审计

2026-10-17；仅候选源码/隔离 fixture，无 live 操作、无新 supervisor、无核心修改。依据原 `04-verification-matrix.md` V22 与 `03-implementation-plan.md` W13：能区分 liveness 与治理进展、日志失败收口、复用监督且无无限 restart storm。原文没有要求卡住后自动恢复，也没有要求 service 整个生命期累计最多 N 次启动。

| 原子要求 | 具体证据 | 判断 |
|---|---|---|
| 活进程与治理进展分开 | `tests/stability_next/test_external_progress_observer.py`：真实 generic 子进程活着；实际 daemon progress reader 判 stale；实际 status 给出旧 policy age；不调用 run_once/init_db/Gateway，也不更新 latest | 证明外部只读观察可见 stale，不是实际 daemon hang 恢复演练；符合“能辨”的有限要求，不声称自动处置 |
| 普通轮失败不会高频忙重试 | `test_self_progress.py:test_daemon_loop_records_redacted_exception_and_runs_next_interval`：实际 loop 在异常后经过 interval sleep，第二轮成功；异常脱敏 | 已有明确断言 |
| 失败证据无法落盘退出并释放锁 | `test_self_progress.py:test_daemon_loop_event_write_failure_exits_and_closes_lock`：main 返回2、锁关闭、run_once一次、无sleep；锁竞争另有关闭测试 | 已有明确断言 |
| 普通日志 open 失败不会留锁/内部无限retry | 新 `test_log_failure_supervision.py`：实际 log_line 向临时目录 append，真实 IsADirectoryError；actual daemon_loop finally 关锁，init_db一次，run_once/sleep均零次 | normal / -O 各1 test通过。只证明交还既有进程监督，不把异常传播伪装成友好日志或自动修复 |
| 复用监督，无无限 restart storm | 仓库 service 为 Type=simple/Restart=always/RestartSec=10；主 agent 提供 live effective metadata 同时为 StartLimitInterval=10、Burst=5、Watchdog=0 | 有明确重启速率约束；不能声称有累计次数上限或 Watchdog hang 恢复。原始 live metadata 由主 agent 归档，不是本子任务独立远端实查 |

## 速率与次数不能混称

`RestartSec=10` 限制的是退出后的重试频率；StartLimit 的10秒窗口、5次 burst 在这种10秒重启间隔下通常不会触发累计停机。因此持续失败可能长期每约10秒再次启动。它不是“总次数有界”，不能写成“5次后永久停止”。

但持续、有间隔的可恢复重试与不受控的立即重启风暴并不等价。原 V22/W13 未要求 fail-stop 总次数、自动判断语义健康或新增 watchdog。不能仅因没有累计次数上限，就新增一个必须改 service/timer/worker 的 G2 阻塞项。该行为应如实记录为 rate-bounded retry；其可用性取舍在后续运维策略中明确。

## 最小出口与限制

在主 agent 的 effective service metadata、外部 observer 新测试、既有 self-progress 测试及本次真实日志失败测试被最终 pin 的资格流程覆盖后，未发现还必须新增长期监督机制才能满足原 V22 的缺口。当前各测试通过不自行等于最终源码整体验收；它们还需纳入对应 source manifest/正常与 optimized 结果。

新测试命令：`python3 [-O] -m unittest discover -s tests/stability_next -p test_log_failure_supervision.py`，C 工作树，均 exit0/1 test/无skip。日志在 G2 dossier 的 `logs/log-failure-supervision-normal-20261017.log` 与 `logs/log-failure-supervision-optimized-20261017.log`。

若产品后来要求永久 hang 自动恢复、失败累计 N 次后停机、或人工复位闭环，则是明确的新监督行为设计，应另设成功条件与授权；本审计既没有实现，也没有提前承诺。
