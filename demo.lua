-- 演示脚本：用来验证 luapack 编译 + 加密 + 运行时解密加载 全链路
-- 打包后这个文件的原文本绝不会出现在产物里

local M = {}

local function fib(n)
  if n < 2 then return n end
  return fib(n - 1) + fib(n - 2)
end

local seq = {}
for i = 1, 12 do seq[#seq + 1] = fib(i) end

local words = { "luapack", "lua", "bytecode", "encrypt", "loader" }
table.sort(words)

M.version = "1.0"
M.seq = table.concat(seq, ",")
M.words = table.concat(words, "|")

function M.greet(name)
  return "[demo] hello, " .. tostring(name) .. " | fib: " .. M.seq
end

-- 自定义函数（外部可调用）：验证字节码真跑起来了
function M.checksum(s)
  local h = 5381
  for i = 1, #s do
    h = (h * 33 + s:byte(i)) % 4294967296
  end
  return h
end

print(M.greet("luapack"))
print("[demo] checksum('hello luapack') = " .. M.checksum("hello luapack"))

return M
