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
local send_data = http2.send_data

local send_ping = http2.send_ping
local read_ping = http2.read_ping

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
local ipairs = ipairs
local assert = assert
local tonumber = tonumber
local tostring = tostring

local find = string.find
local fmt = string.format
local match = string.match

local ceil = math.ceil
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
    local host, p
    local _, Bracket_Pos = find(domain_port, '[%[%]]')
    if Bracket_Pos then
      host, p = match(domain_port, '%[(.+)%][:]?(%d*)')
    else
      host, p = match(domain_port, '([^:]+)[:](%d*)')
    end
    if not host then
      return nil, "4. invalide host or port: " .. domain_port
    end
    domain = host
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

  for i = 1, 2 do
    local head, err = read_head(sock)
    if not head then
      return nil, "Handshake timeout."
    end
    if head.version == 1.1 then
      return nil, "The server does not yet support the http2 protocol."
    end
    local tname = TYPE_TAB[head.type]
    if tname == "SETTINGS" then
      if head.length == 0 then send_settings_ack(sock) break end
      local s, errno = read_settings(sock, head)
      if not s then
        send_goaway(sock, ERRNO_TAB[errno])
        return nil, "recv Invalid `SETTINGS` header."
      end
      settings = s
    elseif tname == "WINDOW_UPDATE" then
      local window = read_window_update(sock, head)
      if not window then
        return nil, "Invalid handshake in `WINDOW_UPDATE` frame."
      end
      settings["SETTINGS_INITIAL_WINDOW_SIZE"] = window.window_size
    else
      return nil, "Invalid `frame type` in handshake."
    end
  end

  for key, value in pairs(SETTINGS_TAB) do
    if type(key) == 'string' and not settings[key] then
      settings[key] = value
    end
  end

  if type(settings) ~= 'table' then
    return nil, "Invalid handshake."
  end

  settings['head'] = nil
  settings['ack'] = nil
  return settings
end

local function read_response(self, sid, timeout)
  local waits = self.wait_cos
  if tonumber(timeout) and tonumber(timeout) > 0.1 then
    waits[sid].timer = ctimeout(timeout, function( ... )
      waits[sid].cancel = true
      cwakeup(waits[sid].co, nil, "request timeout.")
      self:send(function() return send_rstframe(self.sock, sid, 0x00) end)
    end)
  end
  if not self.read_co then
    
    local sock = self.sock
    self.read_co = cfork(function ()
      while 1 do
        local head, err = read_head(sock)
        if not head then
          break
        end
        local tname = head.type_name
        -- 无效的帧类型应该被直接忽略
        if not tname then
          err = "Unexpected frame type received."
          break
        end
        if tname == "GOAWAY" then
          local info = read_goaway(sock, head)
          return nil, fmt("{errcode = %d, errinfo = '%s'%s}", info.errcode, info.errinfo, info.trace and ', trace = ' .. info.trace or '')
        end
        if tname == "RST_STREAM" then
          local info = read_rstframe(sock, head)
          local ctx = waits[head.stream_id]
          if ctx then
            cwakeup(ctx.co, nil, fmt("{ errcode = %d, errinfo = '%s'}", info.errcode, info.errinfo))
            if ctx.timer then
              ctx.timer:stop()
              ctx.timer = nil
            end
            waits[head.stream_id] = nil
          end
        end
        -- 应该忽略PUSH_PROMISE帧
        if tname == "PUSH_PROMISE" then
          local pid, hds = read_promise(sock, head)
          if pid and hds then
            -- 实现虽然拒绝推送流, 但是流推的头部需要被解码
            self:send(function() return send_rstframe(sock, pid, 0x00) end)
            self.hpack:decode(hds)
            -- var_dump(h)
          end
        end
        if tname == "PING" then
          local payload = read_ping(sock, head)
          local tab = flag_to_table(tname, head.flags)
          if tab.ack ~= true then
            -- 回应PING
            self:send(function() return send_ping(sock, 0x01, payload) end)
            -- 主动PING
            self:send(function() return send_ping(sock, 0x00, payload) end)
          end
        end
        if tname == "SETTINGS" then
          if head.length > 0 then
            local _ = read_settings(sock, head)
            self:send(function() return send_settings_ack(sock) end )
          end
        end
        if tname == "WINDOW_UPDATE" then
          local window = read_window_update(sock, head)
          if not window then
            err = "Invalid handshake in `WINDOW_UPDATE` frame."
            break
          end
          self:send(function() return send_window_update(sock, window.window_size) end)
        end
        if tname == "HEADERS" then
          -- print("HEADERS", head.stream_id)
          local ctx = waits[head.stream_id]
          local headers = ctx["headers"]
          -- print(ctx, headers)
          if ctx and headers then
            headers[#headers+1] = read_headers(sock, head)
          end
          local tab = flag_to_table(tname, head.flags)
          if tab.end_stream then
            if #ctx["body"] > 0 then
              ctx["body"] = concat(ctx["body"])
            end
            ctx["headers"] = self.hpack:decode(concat(headers))
            if not ctx.cancel then
              cwakeup(ctx.co, ctx)
              if ctx.timer then
                ctx.timer:stop()
                ctx.timer = nil
              end
            end
            waits[head.stream_id] = nil
          end
        end
        if tname == "DATA" then
          -- print("DATA", head.stream_id)
          local ctx = waits[head.stream_id]
          local body = ctx["body"]
          -- print(ctx, body)
          if ctx and body then
            body[#body+1] = read_data(sock, head)
          end
          local tab = flag_to_table(tname, head.flags)
          if tab.end_stream then
            if #ctx["headers"] > 0 then
              ctx["headers"] = self.hpack:decode(concat(ctx["headers"]))
            end
            if not ctx.cancel then
              ctx["body"] = concat(body)
              cwakeup(ctx.co, ctx)
              if ctx.timer then
                ctx.timer:stop()
                ctx.timer = nil
              end
            end
            waits[head.stream_id] = nil
          end
        end
      end
    end)
  end
  -- 阻塞协程
  local ctx, err = cwait()
  if not ctx then
    return ctx, err
  end
  local body = ctx["body"]
  local headers = ctx["headers"]
  local compressed = headers["content-encoding"]
  if compressed == "gzip" then
    body = gzuncompress(body)
  elseif compressed == "deflate" then
    body = uncompress(body)
  end
  return { body = body, headers = headers }
end

local function send_request(self, headers, body, timeout)
  local sid = self.sid
  self.sid = new_stream_id(sid)
  local sock = self.sock
  if not self.wait_cos then
    self.wait_cos = {}
  end
  self.wait_cos[sid] = { co = cself(), headers = new_tab(3, 0), body = new_tab(32, 0) }
  -- 发送请求头部
  self:send(function() return send_headers(sock, body and 0x04 or 0x05, sid, headers) end)
  
  -- 发送请求主体
  if body then
    local max_body_size = 32737
    if #body > max_body_size then

    else
      self:send(function() return send_data(sock, 0x01, sid, body) end)
    end
  end
  return read_response(self, sid, timeout)
end

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
    return nil, "Connect to Server failed. "
  end
  -- 指定握手超时时间
  sock._timeout = self.timeout
  local config, err = handshake(sock, opt or {})
  if not config then
    self:close()
    return nil, err
  end
  -- 清除握手超时时间
  sock._timeout = nil
  self.info = info
  self.config = config
  self.sock = sock
  self.hpack = hpack:new(config.SETTINGS_MAX_HEADER_LIST_SIZE)
  return ok
end

function client:send(f)
  if not self.queue then
    self.queue = new_tab(16, 0)
    cfork(function ( ... )
      for _, f in ipairs(self.queue) do
        local ok, err = pcall(f, err)
        if not ok then
          print(err)
        end
      end
      self.queue = nil
    end)
  end
  self.queue[#self.queue+1] = f
end

function client:request(url, method, headers, body, timeout)
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
  local hpack = self.hpack
  local headers = hpack:encode(
    {
      [":method"] = method,
      [":scheme"] = info.scheme,
      [":authority"] = info.domain,
      [":path"] = url .. (args or ""),
    }
  ) .. hpack:encode(
    {
      ["origin"] = info.domain,
      ["accept"] = "*/*",
      ["accept-encoding"] = "gzip, deflate, identity",
      ["content-length"] = body and #body or nil,
      ["user-agent"] = ua.get_user_agent(),
    }
  ) .. hpack:encode(headers)
  return send_request(self, headers, body, timeout)
end

function client:reconnect()
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