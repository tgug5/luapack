--[[ luapack standalone runner | v1.1.0 | Lua 5.1 ]]
-- 用法: lua <name>.run.lua <加密文件> [参数...]
local here = (arg and arg[0] and arg[0]:match("^(.*)[/\\][^/\\]*$")) or "."
local loader = dofile(here .. "/demo.loader.lua")
local enc = ...
if not enc then
  io.stderr:write("usage: lua " .. arg[0] .. " <encrypted.luac.enc> [args...]\n")
  os.exit(1)
end
if not enc:find("[/\\]") then enc = here .. "/" .. enc end
local t = {}
for i = 2, #arg do t[#t + 1] = arg[i] end
loader.run(enc, (table.unpack or unpack)(t))
