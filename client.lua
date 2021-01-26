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
local cf_sleep = cf.sleep

local lz = require"lz"
local uncompress = lz.uncompress
local gzuncompress = lz.gzuncompress

local ua = require "protocol.http.ua"

local protocol = require "lua-http2.protocol"
local TYPE_TAB = protocol.TYPE_TAB
local ERRNO_TAB = protocol.ERRNO_TAB
local SETTINGS_TAB = protocol.SETTINGS_TAB
local FLAG_TO_TABLE = protocol.flag_to_table

local read_head = protocol.read_head

local read_data = protocol.read_data
local send_data = protocol.send_data

local send_ping = protocol.send_ping
local read_ping = protocol.read_ping

local send_magic = protocol.send_magic

local read_promise = protocol.read_promise

local send_rstframe = protocol.send_rstframe
local read_rstframe = protocol.read_rstframe

local send_settings = protocol.send_settings
local read_settings = protocol.read_settings
local send_settings_ack = protocol.send_settings_ack

local send_window_update = protocol.send_window_update
local read_window_update = protocol.read_window_update

local read_headers = protocol.read_headers
local send_headers = protocol.send_headers

local send_goaway = protocol.send_goaway
local read_goaway = protocol.read_goaway

local sys = require "sys"
local new_tab = sys.new_tab

local type = type
local pairs = pairs
local ipairs = ipairs
local assert = assert
local tonumber = tonumber

local os_time = os.time

local find = string.find
local fmt = string.format
local match = string.match

local toint = math.tointeger
local concat = table.concat

local methods = { GET = true, POST = true}

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

local function h2_handshake(sock, opt)

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

  local settings = {}

  for i = 1, 2 do
    local head = read_head(sock)
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
  local waits = self.waits
  if tonumber(timeout) and tonumber(timeout) > 0.1 then
    waits[sid].timer = ctimeout(timeout, function( )
      waits[sid].cancel = true
      cwakeup(waits[sid].co, nil, "request timeout.")
      self:send(function() return send_rstframe(self.sock, sid, 0x00) end)
    end)
  end
  if not self.read_co then
    local head, err
    local sock = self.sock
    self.read_co = cfork(function ()
      while 1 do
        head, err = read_head(sock)
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
          err = fmt("{errcode = %d, errinfo = '%s'%s}", info.errcode, info.errinfo, info.trace and ', trace = ' .. info.trace or '')
          break
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
            local ok, errinfo = self.hpack:decode(hds)
            if not ok then
              err = errinfo
              break
            end
            -- var_dump(h)
          end
        end
        if tname == "PING" then
          local payload = read_ping(sock, head)
          local tab = FLAG_TO_TABLE(tname, head.flags)
          if not tab.ack then
            -- 回应PING
            self:send(function() return send_ping(sock, 0x01, payload) end)
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
          local tab = FLAG_TO_TABLE(tname, head.flags)
          if tab.end_stream then
            if #ctx["body"] > 0 then
              ctx["body"] = concat(ctx["body"])
            end
            local h, errinfo = self.hpack:decode(concat(headers))
            if not h then
              err = errinfo
              break
            end
            ctx["headers"] = h
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
          local tab = FLAG_TO_TABLE(tname, head.flags)
          if tab.end_stream then
            if #ctx["headers"] > 0 then
              local h, errinfo = self.hpack:decode(concat(ctx["headers"]))
              if not h then
                err = errinfo
                break
              end
              ctx["headers"] = h
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
      -- 如果是意外关闭了连接, 则需要框架内部主动回收资源
      if self.connected then
        -- 如果有等待的请求则直接唤醒并且提示失败.
        for _, ctx in pairs(self.waits) do
          -- 如果有定时器则需要关闭
          if ctx.timer then
            ctx.timer:stop()
            ctx.timer = nil
          end
          cwakeup(ctx.co, nil, err or "The http2 server unexpectedly closed the network connection.")
        end
        self.connected = false
      end
      -- 回收资源
      self:close()
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
  else
    if type(body) == 'table' then
      body = concat(body)
    end
  end
  return { body = body, headers = headers }
end

local function send_request(self, headers, body, timeout)
  local sock = self.sock
  local sid = self.sid
  self.sid = new_stream_id(sid)
  self.waits[sid] = { co = cself(), headers = new_tab(3, 0), body = new_tab(32, 0) }
  -- 发送请求头部
  self:send(function() return send_headers(sock, body and 0x04 or 0x05, sid, headers) end)

  -- 发送请求主体
  if body then
    local max_body_size = 32737
    if #body > max_body_size then
      -- TODO
      assert(nil, "Prohibit sending http2 payloads that need to be subcontracted.")
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
  self.connected = false
  self.domain = opt.domain
  self.sid = new_stream_id()
  -- self.keepalives = 120
  self.waits = new_tab(0, 64)
end

-- function client:keepalive(timeout)
--   self.keepalives = toint(timeout) and toint(timeout) > 120 and toint(timeout) or 120
-- end

function client:connect(opt)
  if not self.info then
    local info, err = split_domain(self.domain)
    if not info then
      return nil, err
    end
    self.info = info
  end
  local sock = tcp:new()
  local ok = sock:connect(self.info.domain, self.info.port)
  if not ok then
    self:close()
    return nil, "Connect to Server failed. "
  end
  if self.info.scheme == "https" then
    sock:ssl_set_alpn('h2')
    if not sock:ssl_handshake(self.info.domain) then
      self:close()
      return nil, "The server not support tls."
    end
    if sock:ssl_get_alpn() ~= 'h2' then
      self:close()
      return nil, "The server not support http2 protocol in tls."
    end
  end
  if not ok then
    self:close()
    return nil, "Connect to Server failed. "
  end
  -- 指定握手超时时间
  sock._timeout = self.timeout
  local config, err = h2_handshake(sock, opt or {})
  if not config then
    self:close()
    return nil, err
  end
  -- 需要定期发送ping消息保持连接
  -- self.keeper = cf.at(self.keepalives, function()
  --   if not self.connected then
  --     return
  --   end
  --   return self:send(function ( )
  --     if not send_ping(self.sock, 0x00, string.rep('\x00', 8)) then
  --       self:close()
  --       return false
  --     end
  --     return true
  --   end)
  -- end)
  -- 清除握手超时时间
  sock._timeout = nil
  self.connected = true
  self.config = config
  self.sock = sock
  self.hpack = hpack:new(config.SETTINGS_MAX_HEADER_LIST_SIZE)
  return self
end

function client:send(f)
  if not self.queue then
    self.queue = new_tab(16, 0)
    cfork(function ( )
      for _, func in ipairs(self.queue) do
        local ok = pcall(func)
        if not ok then
          break
        end
        self.lasttime = os_time()
      end
      self.queue = nil
    end)
  end
  self.queue[#self.queue+1] = f
end

function client:request(url, method, headers, body, timeout)
  if not self.connected then
    return nil, "http2 client not connected to the server or session was closed."
  end
  if type(url) ~= 'string' or url == '' then
    return nil, "Invalid request url."
  end
  if type(method) ~= 'string' or method == '' or not methods[method:upper()] then
    return nil, "Invalid request method."
  end
  if type(headers) ~= 'table' then
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
      [":method"] = method:upper(),
      [":scheme"] = info.scheme,
      [":authority"] = info.domain,
      [":path"] = url .. (args or ""),
    }
  ) .. hpack:encode(
    {
      ["origin"] = info.domain,
      ["host"] = info.domain,
      ["accept"] = "*/*",
      ["accept-encoding"] = "gzip, deflate, identity",
      ["content-length"] = body and #body or nil,
      ["user-agent"] = ua.get_user_agent(),
    }
  ) .. hpack:encode(headers or {})
  return send_request(self, headers, body, timeout)
end

-- 需要保证多次调用此方法是无害的.
function client:close( )
  self.connected = false
  if self.hpack then
    self.hpack = nil
  end
  if self.timer then
    self.timer:stop()
    self.timer = nil
  end
  -- if self.keeper then
  --   self.keeper:stop()
  --   self.keeper = nil
  -- end
  if self.sock then
    self.sock:close()
    self.sock = nil
  end
end

return client