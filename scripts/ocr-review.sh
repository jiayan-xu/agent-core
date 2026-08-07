#!/usr/bin/env bash
# OpenCodeReview 门禁运行器 —— CI 与本地 git hook 共用
# 退出码: 0=成功(无发现 或 仅报告); 1=门禁触发(有发现且 --gate); 2=ocr 运行异常
#
# 用法:
#   ocr-review.sh [--gate] [--ocr-bin PATH] [ocr review 的其它参数...]
#   例: ocr-review.sh --gate --from origin/main --to HEAD
#   例: ocr-review.sh --from HEAD~3 --to HEAD
#
# 环境变量:
#   OCR_BIN   : 显式指定 ocr 二进制(默认: 优先 PATH 中的 ocr, 未找到则退化 npx; Windows 本机直跑 node 请经此变量或 --ocr-bin 指定)
#   OCR_GATE  : 设为 1 时等价于传 --gate
set -uo pipefail

OCR_BIN="${OCR_BIN:-}"
if [ -z "$OCR_BIN" ]; then
  if command -v ocr >/dev/null 2>&1; then
    OCR_BIN="ocr"
  else
    # 未安装到 PATH 时兜底 npx（联网拉取）。
    # Windows 本机直跑 node 的用法（避开 MSYS/Cygwin 对 /c/... 的路径转换坑）：
    #   OCR_BIN="<node.exe 绝对路径> <ocr.js 绝对路径>" 或 ocr-review.sh --ocr-bin "..."
    OCR_BIN="npx -y @alibaba-group/open-code-review"
  fi
fi

GATE=0
[ "${OCR_GATE:-0}" = "1" ] && GATE=1
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --gate) GATE=1; shift;;
    --ocr-bin)
      if [ $# -lt 2 ]; then
        echo "[ocr] 错误: --ocr-bin 需要参数"; exit 2
      fi
      OCR_BIN="$2"; shift 2;;
    *) ARGS+=("$1"); shift;;
  esac
done

# 默认排除噪声（build 产物 / 备份 / 数据 / 缓存），避免无谓消耗 token
DEFAULT_EXCLUDE=".github/**,.githooks/**,scripts/ocr-review.sh,**/__pycache__/**,**/*.bak,**/*.exe,**/*.csv,**/target/**"
has_exclude=0
for a in "${ARGS[@]:-}"; do [ "$a" = "--exclude" ] && has_exclude=1; done
if [ "$has_exclude" = "0" ]; then ARGS+=("--exclude" "$DEFAULT_EXCLUDE"); fi

# 拆分 OCR_BIN 为命令+参数数组，避免 eval 二次解析（防注入）
read -r -a OCR_CMD <<< "$OCR_BIN"
echo "[ocr] 运行: ${OCR_CMD[*]} review ${ARGS[*]}"
OUT=$( "${OCR_CMD[@]}" review "${ARGS[@]}" 2>&1 )
RC=$?
printf '%s\n' "$OUT"
if [ $RC -ne 0 ]; then
  echo "[ocr] review 进程异常退出(rc=$RC)"; exit 2
fi

# 解析评论数：容忍多种输出格式（`N finding(s)` / `N findings` / `N 条评论` / `N comments`）。
# 逐行扫描、跨全部 pattern 取"最后一个匹配数字"，锚定最终汇总行——
# 避免进度行（如 `0 findings`）干扰，也避免 break 在首个匹配处漏掉真实汇总。
# 若完全无法解析，fail-closed（exit 2）而非静默 0。
FINDINGS=""
last_num=""
while IFS= read -r line; do
  for pat in '[0-9]+ finding(s)?' '[0-9]+ 条评论' '[0-9]+ comments?' '[0-9]+ issues?'; do
    m=$(printf '%s\n' "$line" | grep -oiE "$pat" | grep -oE '[0-9]+' | tail -1)
    if [ -n "$m" ]; then last_num="$m"; fi
  done
done <<< "$OUT"
FINDINGS="$last_num"
if [ -z "$FINDINGS" ]; then
  echo "[ocr] 无法解析评论数，fail-closed 拦截"; exit 2
fi
echo "[ocr] 评论数 = $FINDINGS"

if [ "$GATE" = "1" ] && [ "$FINDINGS" -gt 0 ]; then
  echo "[ocr] 门禁触发：发现 $FINDINGS 条评论，CI/提交被拦截。"
  echo "       处理后可 'git commit --no-verify' / 'git push --no-verify' 强制跳过(不推荐)。"
  exit 1
fi
exit 0
