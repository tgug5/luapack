#!/usr/bin/env bash
# luapack 一键构建 / 自检 / 示例打包
#
#   bash build.sh            自检 + 编译 C 库 + 打示例
#   bash build.sh demo       只打示例
#   bash build.sh ctest      只编译 C 库并跟 Python 产物对拍
#
set -e
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
MODE="${1:-all}"

banner() { printf '\n\033[1m======== %s ========\033[0m\n' "$1"; }

if [ "$MODE" = "all" ] || [ "$MODE" = "selftest" ]; then
  banner "自检（加密算法 / 容器 / 编译链路 / Lua 运行时 loader 实跑）"
  "$PY" luapack.py selftest
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "ctest" ]; then
  banner "编译 C 运行时库 + 测试程序"
  mkdir -p build
  gcc -O2 -Wall -Wextra -o build/lpk_test c/test_luapack_c.c c/luapack_c.c
  echo "  -> build/lpk_test"
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "demo" ] || [ "$MODE" = "ctest" ]; then
  banner "打包示例（三个 Lua 版本，xxtea + aes）"
  for V in 5.1 5.3 5.4; do
    "$PY" luapack.py build test/demo.lua -o "build/demo-$V" --lua "$V" --run
  done
  "$PY" luapack.py build test/demo.lua -o "build/demo-aes" --lua 5.3 -m aes
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "ctest" ]; then
  banner "C 库与 Python 产物逐字节对拍"
  for V in 5.1 5.3 5.4; do
    "bin/luac-$V" -s -o "build/ref-$V.luac" test/demo.lua
    PW=$(cat "build/demo-$V/keys/demo.key")
    ./build/lpk_test "build/demo-$V/demo.luac.enc" "$PW" "build/c-$V.bin" >/dev/null
    if cmp -s "build/ref-$V.luac" "build/c-$V.bin"; then
      echo "  [ok] Lua $V  C 端解密结果与原始字节码一致"
    else
      echo "  [x ] Lua $V  不一致！"; exit 1
    fi
  done
fi

banner "完成，产物在 build/"
