--[[
编写作者:

  Author: CandyMi[https://github.com/candymi]

编写日期:

  2020-11-06
]]

local cf = require "cf"

local tcp = require "internal.TCP"

local hpack = require "lhpack"

local new_tab = require"sys".new_tab

local url = require "url"
local urldecode = url.decode

local xml = require "xml2lua"
local xmlparse = xml.parser

local json = require "json"
local json_decode = json.decode

local protocol = require "protocol.http2.protocol"
local TYPE_TAB = protocol.TYPE_TAB
local ERRNO_TAB = protocol.ERRNO_TAB
local SETTINGS_TAB = protocol.SETTINGS_TAB
local FLAG_TO_TABLE = protocol.flag_to_table


local read_goaway = protocol.read_goaway
local send_goaway = protocol.send_goaway

local read_magic = protocol.read_magic

local read_head = protocol.read_head

local read_data = protocol.read_data
local send_data = protocol.send_data

local read_headers = protocol.read_headers
local send_headers = protocol.send_headers

local read_settings = protocol.read_settings
local send_settings = protocol.send_settings
local send_settings_ack = protocol.send_settings_ack

local read_window_update = protocol.read_window_update
local send_window_update = protocol.send_window_update

local type = type
local pairs = pairs
local tonumber = tonumber

local sub = string.sub
local find = string.find
local match = string.match
local gmatch = string.gmatch
local toint = math.tointeger
local concat = table.concat

local function url_decode(body)
  if type(body) ~= 'string' then
    return
  end
  local ARGS = {}
  for key, value in gmatch(body, "([^&]-)=([^&]+)") do
    local tname, kname = match(urldecode(key), "(.+)%[(.+)%]$")
    if tname and kname then
      local t = ARGS[tname]
      if not t then
        t = new_tab(8, 8)
        ARGS[tname] = t
      end
      t[tonumber(kname) or kname] = urldecode(value)
    else
      ARGS[urldecode(key)] = urldecode(value)
    end
  end
  return ARGS
end

-- 处理ARGS和BODY
local function DISPATCH_HEADER_AND_BODY(headers, bodys)
  local req = { headers = headers }
  local s = find(headers[":path"], '?')
  if s then
    req.args = url_decode(sub(headers[":path"], s + 1))
  end
  if headers[":method"] == "GET" or headers[":method"] == "POST" then
    local content_type = match(headers["content-type"] or '', "([^ ;]+)")
    if content_type == "application/x-www-form-urlencoded" then
      for k, v in pairs(url_decode(bodys) or {}) do
        if not req.args then
          req.args = {}
        end
        req.args[urldecode(k)] = type(v) == "string" and urldecode(v) or v
      end
    elseif content_type == "application/json" then
      for k, v in pairs(json_decode(bodys) or {}) do
        if not req.args then
          req.args = {}
        end
        req.args[k] = v
      end
    elseif content_type == "application/xml" or content_type == "text/xml" then
      for k, v in pairs(xmlparse(bodys) or {}) do
        if not req.args then
          req.args = {}
        end
        req.args[k] = v
      end
    else
      req.body = bodys
    end
  elseif headers[":method"] == "DELETE" or headers[":method"] == "PUT" then
  elseif headers[":method"] == "HEAD" or headers[":method"] == "OPTIONS" then
  end
  return req
end

local function DISPATCH(self, sock, ipaddr)
  local sid = 1
  local h = hpack:new(4096)
  local requests = {}
  local priority = {}
  while 1 do
    local head, err = read_head(sock)
    if not head then
      break
    end
    local tname = TYPE_TAB[head.type]
    if tname == "SETTINGS" then
      if head.length > 0 then
        local _ = read_settings(sock, head)
        send_settings_ack(sock)
      end
    end
    if tname == "WINDOW_UPDATE" then
      local window = read_window_update(sock, head)
      if not window then
        break
      end
      send_window_update(sock, window.window_size)
    end
    if tname == "HEADERS" then
      local tab = FLAG_TO_TABLE(tname, head.flags)
      local stream_id = head.stream_id
      if sid > stream_id then
        -- priority 帧有预留则保留此流ID, 否则当做协议错误处理
        local pri = priority[stream_id]
        if not pri then
          send_goaway(sock, ERRNO_TAB["PROTOCOL_ERROR"])
          break
        end
        -- 预留的sid需要被清除掉
        if pri then
          priority[stream_id] = nil
        end
      end
      -- 取出request内的流ID上下文, 如果没有就创建一个.
      if not requests[stream_id] then
        requests[stream_id] = { headers = {}, body = {} }
      end
      local ctx = requests[stream_id]
      ctx.headers[#ctx.headers+1] = read_headers(sock, head)
      if tab.end_stream then
        requests[stream_id] = nil
        local req = DISPATCH_HEADER_AND_BODY(h:decode(concat(ctx.headers)), concat(ctx.body))
        var_dump(req)
      end
    end
    if tname == "DATA" then
      local tab = FLAG_TO_TABLE(tname, head.flags)
      local stream_id = head.stream_id
      if sid > stream_id then
        -- priority 帧有预留则保留此流ID, 否则当做协议错误处理
        local pri = priority[stream_id]
        if not pri then
          send_goaway(sock, ERRNO_TAB["PROTOCOL_ERROR"])
          break
        end
        -- 预留的sid需要被清除掉
        if pri then
          priority[stream_id] = nil
        end
      end
      -- 取出request内的流ID上下文, 如果没有就创建一个.
      if not requests[stream_id] then
        requests[stream_id] = { headers = {}, body = {} }
      end
      local ctx = requests[stream_id]
      ctx.body[#ctx.body+1] = read_data(sock, head)
      if tab.end_stream then
        requests[stream_id] = nil
        local req = DISPATCH_HEADER_AND_BODY(h:decode(concat(ctx.headers)), concat(ctx.body))
        var_dump(req)
      end
    end
    -- print(tname)
  end
  return sock:close()
end

local function RAW_DISPATCH(fd, ipaddr, self)
  -- print(fd, ipaddr)
  local sock = tcp:new()
  sock:set_fd(fd):timeout(self.__timeout or 15)
  local ok, err = read_magic(sock)
  if not ok then
    return sock:close()
  end

  -- SEND SETTINS
  send_settings(sock, nil, {
    -- SET TABLE SISZE
    -- {0x01, opt.SETTINGS_HEADER_TABLE_SIZE or SETTINGS_TAB["SETTINGS_HEADER_TABLE_SIZE"]},
    -- DISABLE PUSH
    {0x02, 0x00},
    -- SET CONCURRENT STREAM
    {0x03, SETTINGS_TAB["SETTINGS_MAX_CONCURRENT_STREAMS"]},
    -- SET WINDOWS SIZE
    {0x04, SETTINGS_TAB["SETTINGS_INITIAL_WINDOW_SIZE"]},
    -- SET MAX FRAME SIZE
    {0x05, SETTINGS_TAB["SETTINGS_MAX_FRAME_SIZE"]},
    -- SET SETTINGS MAX HEADER LIST SIZE
    {0x06, SETTINGS_TAB["SETTINGS_MAX_HEADER_LIST_SIZE"]},
  })
  -- 是否必须要发送呢?
  -- send_window_update(sock, 2 ^ 24 - 1)
  return DISPATCH(self, sock, ipaddr)
end

local function SSL_DISPATCH(fd, ipaddr, self)
  local sock = tcp:new()
  sock:set_fd(fd):timeout(self.__timeout or 15)
  local ok, err = read_magic(sock)
  if not ok then
    return sock:close()
  end


  -- SEND SETTINS
  send_settings(sock, nil, {
    -- SET TABLE SISZE
    -- {0x01, opt.SETTINGS_HEADER_TABLE_SIZE or SETTINGS_TAB["SETTINGS_HEADER_TABLE_SIZE"]},
    -- DISABLE PUSH
    {0x02, 0x00},
    -- SET CONCURRENT STREAM
    {0x03, SETTINGS_TAB["SETTINGS_MAX_CONCURRENT_STREAMS"]},
    -- SET WINDOWS SIZE
    {0x04, SETTINGS_TAB["SETTINGS_INITIAL_WINDOW_SIZE"]},
    -- SET MAX FRAME SIZE
    {0x05, SETTINGS_TAB["SETTINGS_MAX_FRAME_SIZE"]},
    -- SET SETTINGS MAX HEADER LIST SIZE
    {0x06, SETTINGS_TAB["SETTINGS_MAX_HEADER_LIST_SIZE"]},
  })

  send_window_update(sock, 2 ^ 24 - 1)

  return DISPATCH(self, sock, ipaddr)
end

local class = require "class"

local server = class("http2-server")

function server:ctor(opt)
  self.sock = tcp:new()
end

function server:listen(ip, port, backlog)
  assert(type(ip) == 'string' and toint(port) and toint(port) > 0 and toint(port) < 65536, "http2d error: invalid ip or port")
  self.ip, self.port = ip, toint(port)
  self.sock:set_backlog(toint(backlog) and toint(backlog) > 128 and toint(backlog))
  return assert(self.sock:listen(ip or "0.0.0.0", toint(port), function (fd, ipaddr)
      return RAW_DISPATCH(fd, match(ipaddr, '^::[f]+:(.+)') or ipaddr, self)
  end))
end


function server:run( ... )
  return cf.wait()
end


return server