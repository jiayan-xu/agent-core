#!/usr/bin/env python3
# 脱离式可靠启动 agent-core（仿 memoria start_memoria_only.ps1 的 start_new_session 范式）。
# 不硬编码任何密钥：env 从当前会话继承（AGENT_API_KEY / MEMORIA_ADMIN_KEY / SILICONFLOW_API_KEY / VOLCES_API_KEY）。
# 若 MEMORIA_JARVIS_BADGE 未设，则 fallback 到 MEMORIA_ADMIN_KEY（源码 observe_filtered 同逻辑），保证 firehose 以 admin 写 memoria。
import os, sys, subprocess, time

# P0: 禁止硬编码本机用户名绝对路径。运行时基于脚本自身位置推导，跨机器可移植。
_HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(_HERE, "target", "release", "agent-core.exe")
CWD = _HERE
LOG = os.path.join(_HERE, "agent_core_launch.log")

def main():
    if not os.path.exists(EXE):
        print(f"FATAL: exe not found: {EXE}", file=sys.stderr); sys.exit(2)
    env = dict(os.environ)
    if not env.get("MEMORIA_JARVIS_BADGE") and env.get("MEMORIA_ADMIN_KEY"):
        env["MEMORIA_JARVIS_BADGE"] = env["MEMORIA_ADMIN_KEY"]
    # 关键 env 存在性自检（不打印值）
    for k in ("AGENT_API_KEY", "MEMORIA_ADMIN_KEY", "SILICONFLOW_API_KEY", "VOLCES_API_KEY"):
        print(f"[start] env {k}: {'SET' if env.get(k) else 'MISSING'}", file=sys.stderr)
    print(f"[start] MEMORIA_JARVIS_BADGE fallback: {'SET' if env.get('MEMORIA_JARVIS_BADGE') else 'MISSING'}", file=sys.stderr)
    with open(LOG, "ab", buffering=0) as lf:
        lf.write(f"\n=== agent-core launch {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n".encode())
        p = subprocess.Popen(
            [EXE, "--service"],
            cwd=CWD, env=env, stdout=lf, stderr=lf,
            start_new_session=True,  # 脱离父进程会话，harness 退出后存活
        )
        lf.write(f"spawned pid={p.pid}\n".encode())
    print(f"agent-core spawned pid={p.pid} (detached, start_new_session)")

if __name__ == "__main__":
    main()
