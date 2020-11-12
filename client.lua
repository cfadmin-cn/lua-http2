--[[
编写作者:

  Author: CandyMi[https://github.com/candymi]

编写日期:

  2020-11-06
]]

local cf = require "cf"
local cself = cf.self
local cfork = cf.fork
local cwait = cf.wait
local cwakeup = cf.wakeup
local ctimeout = cf.timeout

local lz = require"lz"
local uncompress = lz.uncompress
local gzuncompress = lz.gzuncompress

local ua = require "protocol.http.ua"

local http2 = require "protocol.http2.protocol"
local TYPE_TAB = http2.TYPE_TAB
local ERRNO_TAB = http2.ERRNO_TAB
local SETTINGS_TAB = http2.SETTINGS_TAB
local flag_to_table = http2.flag_to_table

local read_head = http2.read_head
local read_data = http2.read_data

local send_magic = http2.send_magic

local read_promise = http2.read_promise

local send_rstframe = http2.send_rstframe
local read_rstframe = http2.read_rstframe

local send_settings = http2.send_settings
local read_settings = http2.read_settings
local send_settings_ack = http2.send_settings_ack

local send_window_update = http2.send_window_update
local read_window_update = http2.read_window_update

local read_headers = http2.read_headers
local send_headers = http2.send_headers

local send_goaway = http2.send_goaway
local read_goaway = http2.read_goaway

local sys = require "sys"
local new_tab = sys.new_tab

local type = type
local next = next
local pairs = pairs
local assert = assert
local tonumber = tonumber
local tostring = tostring

local find = string.find
local fmt = string.format
local match = string.match
local toint = math.tointeger
local concat = table.concat

-- 必须遵守此stream id递增规则
local function new_stream_id(num)
  if not toint(num) or num < 1 then
    return 1
  end
  return (num + 2) & 2147483647
end

-- 分割domain
local function split_domain(domain)
  if type(domain) ~= 'string' or domain == '' or #domain < 8 then
    return nil, "Invalid http[s] domain."
  end
  local scheme, domain_port = match(domain, "^(http[s]?)://([^/]+)")
  if not scheme or not domain_port then
    return nil, "Invalid `scheme` : http/https."
  end

  local port = scheme == "https" and 443 or 80
  local domain = domain_port
  if find(domain_port, ':') then
    local d, p
    local _, Bracket_Pos = find(domain_port, '[%[%]]')
    if Bracket_Pos then
      d, p = match(domain_port, '%[(.+)%][:]?(%d*)')
    else
      d, p = match(domain_port, '([^:]+)[:](%d*)')
    end
    if not d then
      return nil, "4. invalide host or port: " .. domain_port
    end
    domain = d
    port = toint(p) or port
  end

  assert(port >= 1 and port <= 65535, "Invalid Port :" .. port)

  return { scheme = scheme, domain = domain, port = port }
end

local function handshake(sock, opt)

  -- SEND MAGIC BYTES
  send_magic(sock)

  -- SEND SETTINS
  send_settings(sock, nil, {
    -- SET TABLE SISZE
    -- {0x01, opt.SETTINGS_HEADER_TABLE_SIZE or SETTINGS_TAB["SETTINGS_HEADER_TABLE_SIZE"]},
    -- DISABLE PUSH
    {0x02, opt.SETTINGS_ENABLE_PUSH or 0x00},
    -- SET CONCURRENT STREAM
    {0x03, opt.SETTINGS_MAX_CONCURRENT_STREAMS or SETTINGS_TAB["SETTINGS_MAX_CONCURRENT_STREAMS"]},
    -- SET WINDOWS SIZE
    {0x04, opt.SETTINGS_INITIAL_WINDOW_SIZE or SETTINGS_TAB["SETTINGS_INITIAL_WINDOW_SIZE"]},
    -- SET MAX FRAME SIZE
    {0x05, opt.SETTINGS_MAX_FRAME_SIZE or SETTINGS_TAB["SETTINGS_MAX_FRAME_SIZE"]},
    -- SET SETTINGS MAX HEADER LIST SIZE
    {0x06, opt.SETTINGS_MAX_HEADER_LIST_SIZE or SETTINGS_TAB["SETTINGS_MAX_HEADER_LIST_SIZE"]},
  })

  send_window_update(sock, 2 ^ 24 - 1)

  local settings

  while 1 do
    local head, err = read_head(sock)
    if not head then
      send_goaway(sock, ERRNO_TAB["SETTINGS_TIMEOUT"])
      return nil, err
    end
    if head.version == 1.1 then
      return nil, "The server does not support the http2 protocol."
    end
    local tname = TYPE_TAB[head.type]
    if not tname or head.stream_id ~= 0 then
      -- var_dump(head)
      send_goaway(sock, ERRNO_TAB["PROTOCOL_ERROR"])
      return nil, "Invalid `Frame Type` In handshake."
    end
    if tname == "SETTINGS" then
      if head.length == 0 then
        send_settings_ack(sock)
        break
      end
      local s, errno = read_settings(sock, head)
      if not s then
        send_goaway(sock, ERRNO_TAB[errno])
        return nil, "recv Invalid `SETTINGS` header."
      end
      settings = s
    end
    if tname == "WINDOW_UPDATE" then
      local window = read_window_update(sock, head)
      if type(settings) == 'table' then
        settings["SETTINGS_INITIAL_WINDOW_SIZE"] = window.window_size
      end
    end
    if tname == "GOAWAY" then
      local info = read_goaway(sock, head)
      return nil, fmt("{errcode = %d, errinfo = '%s'%s}", info.errcode, info.errinfo, info.trace and ', trace = ' .. info.trace or '')
    end
  end

  if type(settings) ~= 'table' then
    return nil, "Invalid Handshake"
  end

  for key, value in pairs(SETTINGS_TAB) do
    if type(key) == 'string' and not settings[key] then
      settings[key] = value
    end
  end

  sock._timeout = nil
  settings['head'] = nil
  settings['ack'] = nil
  return settings
end

local function send_request(self, headers, body, timeout)
  -- 检查实现是否正确
  local waits = self.waits
  if waits[tostring(self.sid)] then
    return assert(nil, "Invalid request in sid : " .. self.sid)
  end
  -- 得到对象熟悉
  local sid = self.sid
  self.sid = new_stream_id(sid)
  local sock = self.sock

  -- 记录当前请求对象
  local ctx = { co = cself(), timer = nil }
  waits[tostring(sid)] = ctx

  -- 发送请求头部
  send_headers(sock, body and 0x04 or 0x05, sid, headers)
  -- 发送请求主体
  if body then
    send_data(sock, nil, sid, body)
  end

  timeout = tonumber(timeout)
  if timeout >= 0.1 then
    ctx.timer = ctimeout(timeout, function()
      local co = ctx.co
      ctx.co = nil
      ctx.timer = nil
      waits[tostring(sid)] = nil
      return cwakeup(co, nil, "Request was timeout.")
    end)
  end
  
  -- 当响应返回的时候, 将会被自动唤醒
  return cwait()
end

-- local client = { version = "0.1", timeout = 5 }

-- function client.handshake(sock, opt)

--   -- 指定握手超时时间
--   sock._timeout = client.timeout

--   -- SEND MAGIC BYTES
--   send_magic(sock)

--   -- SEND SETTINS
--   send_settings(sock, nil, {
--     -- SET TABLE SISZE
--     -- {0x01, opt.SETTINGS_HEADER_TABLE_SIZE or SETTINGS_TAB["SETTINGS_HEADER_TABLE_SIZE"]},
--     -- DISABLE PUSH
--     {0x02, 0x00 or opt.SETTINGS_ENABLE_PUSH or SETTINGS_TAB["SETTINGS_ENABLE_PUSH"]},
--     -- SET CONCURRENT STREAM
--     {0x03, opt.SETTINGS_MAX_CONCURRENT_STREAMS or SETTINGS_TAB["SETTINGS_MAX_CONCURRENT_STREAMS"]},
--     -- SET WINDOWS SIZE
--     {0x04, opt.SETTINGS_INITIAL_WINDOW_SIZE or SETTINGS_TAB["SETTINGS_INITIAL_WINDOW_SIZE"]},
--     -- SET MAX FRAME SIZE
--     {0x05, opt.SETTINGS_MAX_FRAME_SIZE or SETTINGS_TAB["SETTINGS_MAX_FRAME_SIZE"]},
--     -- SET SETTINGS MAX HEADER LIST SIZE
--     {0x06, opt.SETTINGS_MAX_HEADER_LIST_SIZE or SETTINGS_TAB["SETTINGS_MAX_HEADER_LIST_SIZE"]},
--   })

--   send_window_update(sock, 2 ^ 24 - 1)

--   local settings

--   while 1 do
--     local head, err = read_head(sock)
--     if not head then
--       send_goaway(sock, ERRNO_TAB["SETTINGS_TIMEOUT"])
--       return nil, err
--     end
--     local tname = TYPE_TAB[head.type]
--     if not tname then
--       send_goaway(sock, ERRNO_TAB["PROTOCOL_ERROR"])
--       return nil, "Invalid `Frame Type` In handshake."
--     end
--     if tname == "SETTINGS" then
--       if head.length == 0 then
--         send_settings_ack(sock)
--         break
--       end
--       local s, errno = read_settings(sock, head)
--       if not s then
--         send_goaway(sock, ERRNO_TAB[errno])
--         return nil, "recv Invalid `SETTINGS` header."
--       end
--       settings = s
--     end
--     if tname == "WINDOW_UPDATE" then
--       local window = read_window_update(sock, head)
--       if type(settings) == 'table' then
--         settings["SETTINGS_INITIAL_WINDOW_SIZE"] = window.window_size
--       end
--     end
--     if tname == "GOAWAY" then
--       local info = read_goaway(sock, head)
--       return nil, fmt("{errcode = %d, errinfo = '%s'%s}", info.errcode, info.errinfo, info.trace and ', trace = ' .. info.trace or '')
--     end
--   end

--   if type(settings) ~= 'table' then
--     return nil, "Invalid Handshake"
--   end

--   for key, value in pairs(SETTINGS_TAB) do
--     if type(key) == 'string' and not settings[key] then
--       settings[key] = value
--     end
--   end

--   sock._timeout = nil
--   settings['head'] = nil
--   settings['ack'] = nil
--   return settings
-- end

-- function client.close(sock)
--   return send_goaway(sock, 0x00) and sock:close()
-- end


-- function client.connect(sock, opt)
--   local ok, err = sock:connect(opt.host, opt.port)
--   if not ok then
--     return nil, err
--   end
--   return client.handshake(sock, opt)
-- end

-- function client.send_request(ctx)
--   local sock = ctx.sock
--   local sid = new_stream_id(ctx.sid)
--   send_headers(sock, nil, sid, ctx.headers)
--   return sid
-- end

-- function client.dispatch_all(ctx)
--   local headers, body
--   local sock = ctx.sock
--   local hpack = ctx.hpack
--   local waits = ctx.waits
--   local response_headers, response_bodys
--   while 1 do
--     local head, err = read_head(sock)
--     if not head then
--       send_goaway(sock, ERRNO_TAB["SETTINGS_TIMEOUT"])
--       return nil, err
--     end
--     local tname = TYPE_TAB[head.type]
--     if tname == "GOAWAY" then
--       local info = read_goaway(sock, head)
--       error(fmt("{errcode = %d, errinfo = '%s'%s}", info.errcode, info.errinfo, info.trace and ', trace = ' .. info.trace or ''))
--     end
--     if tname == "RST_STREAM" then
--       local info = read_rstframe(sock, head)
--       error(fmt("{ errcode = %d, errinfo = '%s'}", info.errcode, info.errinfo))
--     end
--     if tname == "HEADERS" then
--       local header_bytes, err = read_headers(sock, head)
--       if not header_bytes then
--         return nil, err
--       end
--       headers = ctx.hpack:decode(header_bytes)
--     end
--     if tname == "PUSH_PROMISE" then
--       local pid, hds = read_promise(sock, head)
--       if pid and hds then
--         -- 拒绝推送流
--         send_rstframe(sock, pid, 0x00)
--         local h = hpack:decode(hds)
--         -- var_dump(h)
--       end
--     end
--     if tname == "DATA" then
--       local tab = flag_to_table("DATA", head.flags)
--       if not response then
--         if tab.end_stream then
--           local body = read_data(sock, head)
--           if type(headers) == 'table' then
--             local compressed = headers["content-encoding"] or headers["Content-Encoding"]
--             if compressed == "gzip" then
--               body = gzuncompress(body)
--             elseif compressed == "deflate" then
--               body = uncompress(body)
--             end
--           end
--           response = nil
--           return { headers = headers, body = body }
--         end
--         response = new_tab(32, 0)
--       end
--       response[#response+1] = read_data(sock, head)
--       if tab.end_stream then
--         local body = concat(response)
--         if type(headers) == 'table' then
--           local compressed = headers["content-encoding"] or headers["Content-Encoding"]
--           if compressed == "gzip" then
--             body = gzuncompress(body)
--           elseif compressed == "deflate" then
--             body = uncompress(body)
--           end
--         end
--         response = nil
--         return { headers = headers, body = body }
--       end
--     end
--   end
--   return true
-- end

-- return client

local tcp = require "internal.TCP"

local hpack = require "lhpack"

local class = require "class"

local client = class("http2-client")

function client:ctor(opt)
  self.version = 0.1
  self.timeout = 10
  self.hpack = nil
  self.sock = nil
  self.domain = opt.domain
  self.sid = new_stream_id()
  self.waits = new_tab(0, 64)
end

function client:connect(opt)
  local info, err = split_domain(self.domain)
  if not info then
    return nil, err
  end
  local sock = tcp:new()
  local ok, err
  if info.scheme == "https" then
    -- 如果支持SSL, 则会尝试进行ALPN协商
    if sock.ssl_set_alpn then
      sock:ssl_set_alpn("h2")
    end
    ok, err = sock:ssl_connect(info.domain, info.port)
    if sock.ssl_get_alpn then
      local alpn = sock:ssl_get_alpn()
      if ok and (not find(alpn or '', "h2")) then -- 如果协议不支持ALPN
        self:close()
        return nil, "The server not support http2 protocol in tls."
      end
    end
  else
    ok, err = sock:connect(info.domain, info.port)
  end
  if not ok then
    self:close()
    return nil, "Connect to Server failed."
  end
  -- 指定握手超时时间
  sock._timeout = self.timeout
  local config, err = handshake(sock, opt or {})
  if not config then
    self:close()
    return nil, err
  end
  self.info = info
  self.config = config
  self.sock = sock
  self.hpack = hpack:new(config.SETTINGS_MAX_HEADER_LIST_SIZE)
  return ok
end

function client:send_request(url, method, headers, body, timeout)
  if type(url) ~= 'string' or url == '' then
    return nil, "Invalid request url."
  end
  if type(method) ~= 'string' or method == '' then
    return nil, "Invalid request method."
  end
  if type(headers) ~= 'table' or not next(headers) then
    return nil, "Invalid request headers."
  end
  local args
  if method == "GET" and type(body) == 'string' and body ~= '' then
    args = body
    body = nil
  end
  local info = self.info
  return send_request(self,
    self.hpack:encode({
      [":method"] = method,
      [":scheme"] = info.scheme,
      [":authority"] = info.domain,
      [":path"] = url .. (args or ""),
    }) .. 
    self.hpack:encode({
      ["user-agent"] = ua.get_user_agent(),
      ["origin"] = info.domain,
    }) .. self.hpack:encode(headers), body, timeout)
end

function client:dispatch_all()
  -- body
end

function client:close( ... )
  if self.sock then
    self.sock:close()
    self.sock = nil
  end
  if self.hpack then
    self.hpack = nil
  end
end


return client