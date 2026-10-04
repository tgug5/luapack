--[[ luapack runtime loader | v1.1.0 | Lua 5.1 | AES/XXTEA container ]]

-- ===== 内嵌运行参数（由 luapack 生成，勿手改）=====
local _P = {3884687986, 3488186059, 4171734869, 819535227}
local _MASK = 1282039958
local _SCRAMBLE_N = 32
local _PERM = {20,1,13,18,27,4,28,6,25,31,11,12,8,9,23,10,26,5,16,21,30,7,15,2,22,3,14,24,32,29,17,19}
local _MASKSTR = "\73\98\153\193\169\51\201\176\60\115\69\128\83\87\92\243\97\143\172\133\252\83\126\169\226\123\37\212\47\53\88\181"
local _HEADER = 128
local _LUA_VER = "5.1"

local _KEY = {}
for i = 1, 4 do
  _KEY[i] = (_P[i] - _MASK) % 4294967296
end

local floor = math.floor
local C32 = 4294967296

local X4 = {}
do
  for a = 0, 15 do
    local row = {}
    for b = 0, 15 do
      local r, p, x, y = 0, 1, a, b
      for _ = 1, 4 do
        local xa, yb = x % 2, y % 2
        if xa ~= yb then r = r + p end
        x, y, p = (x - xa) / 2, (y - yb) / 2, p * 2
      end
      row[b] = r
    end
    X4[a] = row
  end
end

local function xor32(a, b)
  local r, p = 0, 1
  for _ = 1, 8 do
    local xa, yb = a % 16, b % 16
    r = r + X4[xa][yb] * p
    a, b, p = (a - xa) / 16, (b - yb) / 16, p * 16
  end
  return r
end

local function x8(a, b)
  return X4[floor(a / 16)][floor(b / 16)] * 16 + X4[a % 16][b % 16]
end

local function add32(a, b)
  local r = a + b
  if r >= C32 then r = r - C32 end
  return r
end

local function sub32(a, b)
  local r = a - b
  if r < 0 then r = r + C32 end
  return r
end

local function shl32(a, n) return (a * (2 ^ n)) % C32 end
local function shr32(a, n) return floor(a / (2 ^ n)) end

local function towords(s)
  local n = #s
  local pad = (4 - n % 4) % 4
  if pad > 0 then s = s .. string.rep("\0", pad) end
  local w, i, m = {}, 1, #s / 4
  for j = 1, m do
    local b1, b2, b3, b4 = s:byte(i, i + 3)
    w[j] = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
    i = i + 4
  end
  return w, m
end

local function tostr(w)
  local t = {}
  for i = 1, #w do
    local x = w[i]
    t[i] = string.char(x % 256, floor(x / 256) % 256,
                       floor(x / 65536) % 256, floor(x / 16777216) % 256)
  end
  return table.concat(t)
end

local DELTA = 0x9E3779B9

local function mx(sum, y, z, p, e, k)
  local a = xor32(shr32(z, 5), shl32(y, 2))
  local b = xor32(shr32(y, 3), shl32(z, 4))
  local idx = xor32(p % 4, e) + 1
  local c = add32(xor32(sum, y), xor32(k[idx], z))
  return xor32(add32(a, b), c)
end

local function xxtea_dec(v, n, k)
  local rounds = 6 + floor(52 / n)
  local sum = (rounds * DELTA) % C32
  local y = v[1]
  for _ = 1, rounds do
    local e = shr32(sum, 2) % 4
    for p = n, 2, -1 do
      local z = v[p - 1]
      v[p] = sub32(v[p], mx(sum, y, z, p - 1, e, k))
      y = v[p]
    end
    local z = v[n]
    v[1] = sub32(v[1], mx(sum, y, z, 0, e, k))
    y = v[1]
    sum = sub32(sum, DELTA)
  end
end

local function unscramble(data)
  local n = _SCRAMBLE_N
  if n < 2 or #data < n then return data end
  local plain = {}
  for i = 1, n do
    plain[i] = string.char(x8(data:byte(i), _MASKSTR:byte((i - 1) % #_MASKSTR + 1)))
  end
  local head = {}
  for dst = 1, n do
    head[_PERM[dst]] = plain[dst]
  end
  return table.concat(head) .. data:sub(n + 1)
end

local function readfile(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local d = f:read("*a")
  f:close()
  return d
end

local function u64le(s, off)
  local v, p = 0, 1
  for i = off, off + 7 do
    v = v + s:byte(i + 1) * p
    p = p * 256
  end
  return v
end

local function decrypt(blob)
  if type(blob) ~= "string" or #blob < _HEADER + 8 then
    return nil, "数据太短，不是合法容器"
  end
  if blob:sub(1, 4) ~= "LPK\1" then
    return nil, "魔数不匹配：不是 luapack 容器"
  end
  if blob:byte(7) ~= 0 then
    return nil, "该容器用的是别的加密算法，纯 Lua loader 解不开"
  end
  local flags = blob:byte(8)
  local plen = u64le(blob, 16)
  local payload = blob:sub(_HEADER + 1, _HEADER + plen)
  if #payload ~= plen then return nil, "数据被截断" end
  local w, n = towords(payload)
  if n < 2 then return nil, "payload 太小" end
  xxtea_dec(w, n, _KEY)
  local body = tostr(w)
  if flags % 2 == 1 then body = unscramble(body) end
  if body:sub(1, 4) ~= "LPBC" then
    return nil, "口令不对或文件损坏"
  end
  local b = { body:byte(5, 8) }
  local ln = b[1] + b[2] * 256 + b[3] * 65536 + b[4] * 16777216
  if 24 + ln > #body then return nil, "长度字段异常" end
  return body:sub(25, 24 + ln)
end

local _M = { lua_version = _LUA_VER }

function _M.decrypt(blob)
  local bc, err = decrypt(blob)
  if not bc then error("luapack: " .. tostring(err), 0) end
  return bc
end

function _M.loadfile(x)
  local blob = x
  if type(x) == "string" and #x < 2048 then
    local d = readfile(x)
    if d then
      blob = d
    elseif x:find("[/\\]") or x:find("%.enc$") or x:find("%.luac") then
      error("luapack: 打不开文件 " .. x, 0)
    end
  end
  local bc = _M.decrypt(blob)
  local fn, err = loadstring(bc, "@demo")
  if not fn then error("luapack: 字节码加载失败: " .. tostring(err), 0) end
  return fn
end

function _M.run(x, ...)
  return _M.loadfile(x)(...)
end

return _M
