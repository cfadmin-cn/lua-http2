--[[
编写作者:

  Author: CandyMi[https://github.com/candymi]

编写日期:

  2020-11-06
]]

local hpack = require "lua-http2.hpack"

-- local lz = require "lz"
-- local decompress = lz.compress
-- local gzcompress = lz.gzcompress

local sys = require "sys"
local now = sys.now
local new_tab = sys.new_tab


local url = require "url"
local urldecode = url.decode

local xml = require "xml2lua"
local xmlparse = xml.parser

local json = require "json"
local json_decode = json.decode

local aio = require "aio"
local aio_stat = aio.stat



local protocol = require "lua-http2.protocol"
local TYPE_TAB = protocol.TYPE_TAB
local ERRNO_TAB = protocol.ERRNO_TAB
local SETTINGS_TAB = protocol.SETTINGS_TAB
local FLAG_TO_TABLE = protocol.flag_to_table

local read_priority = protocol.read_priority

local read_continuation = protocol.read_continuation

local read_rstframe = protocol.read_rstframe
local send_rstframe = protocol.send_rstframe

local read_goaway = protocol.read_goaway
local send_goaway = protocol.send_goaway

local read_magic = protocol.read_magic

local read_head = protocol.read_head

local read_ping = protocol.read_ping
local send_ping = protocol.send_ping

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
local pcall = pcall
local ipairs = ipairs
local tonumber = tonumber

local sub = string.sub
local gsub = string.gsub
local find = string.find
local match = string.match
local gmatch = string.gmatch
local toint = math.tointeger
local concat = table.concat
local os_date = os.date
local tinsert = table.insert

local point = '\x2e'        -- '.'
local point2 = '\x2e\x2e'   -- '..'

local tab_copy
tab_copy = function (src)
  local dst = new_tab(0, 32)
  for k, v in pairs(src) do
    dst[k] = type(v) == 'table' and tab_copy(v) or v
  end
  return dst
end

local function tab_merge(t1, t2)
  for key, value in pairs(t2) do
    t1[key] = value
  end
  return t1
end

-- 检查路径有效性
local function check_path(path)
  local paths = {}
  for pit in gmatch(path, "([^/]+)") do
    tinsert(paths, pit)
  end
  local head, tail = paths[1], paths[#paths]
  if head == point2 or tail == point or tail == point2 then
    return true
  end
	local deep = 1
  for _, p in ipairs(paths) do
    if p ~= point then
      if p == point2 then
        deep = deep - 1
      else
        deep = deep + 1
      end
    end
		if deep <= 0 then
			return true
		end
	end
	return false
end

-- 响应请求
local function make_response(sock, sid, headers, body)
  -- 发送回应客户端
  return send_headers(sock, body and 0x04 or 0x05, sid, headers) and body and send_data(sock, nil, sid, body) or false
end

-- 错误响应
local function error_response(sock, h2pack, sid, code, headers, body)
  return make_response(
    sock, sid,
    h2pack:encode({ [':status'] = toint(code) >= 400 and toint(code) <= 515 and code or 500 }) ..
    h2pack:encode(tab_merge({ ['date'] = os_date("%a, %d %b %Y %X GMT"), ['content-type'] = "text/html; charset=utf-8", ['server'] = "cfadmin/0.1" }, headers or {})),
    type(body) == 'string' and body or nil
  )
end

-- 普通响应
local function normal_response(sock, h2pack, sid, code, headers, body)
  return make_response(
    sock, sid,
    h2pack:encode({ [':status'] = toint(code) >= 200 and toint(code) < 400 and code or 500 }) ..
    h2pack:encode(tab_merge({ ['date'] = os_date("%a, %d %b %Y %X GMT"), ['content-type'] = "text/html; charset=utf-8", ['server'] = "cfadmin/0.1" }, headers or {})),
    type(body) == 'string' and body or nil
  )
end


local function h2_response(self, sock, stream_id, h2pack, opt, req, resp)
  local s, ipaddr = now(), opt.ipaddr
  local routes, foldor = self.routes, self.foldor
  local path = urldecode(req['headers'][':path'] or '')
  path = gsub(sub(path, 1, (find(path, "?") or 0) - 1), '(/[/]+)', '/')
  -- 确认路由是否存在
  local cb = routes[path]
  if not cb then
    -- 是否继续检查静态文件路由
    if not foldor then
      self:tolog(404, req['headers'][':path'], ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or ipaddr, req['headers'][':method'], now() - s)
      return error_response(sock, h2pack, stream_id, 404, {}, nil)
    end
    -- 检查静态文件路径是否合法
    if check_path(path) then
      self:tolog(404, req['headers'][':path'], ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or ipaddr, req['headers'][':method'], now() - s)
      return error_response(sock, h2pack, stream_id, 404, {}, nil)
    end
    local filepath = foldor .. path
    local stat = aio_stat(filepath)
    -- 检查是否为合法的`文件`类型
    if type(stat) ~= 'table' or stat.mode ~= 'file' then
      self:tolog(404, req['headers'][':path'], ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or ipaddr, req['headers'][':method'], now() - s)
      return error_response(sock, h2pack, stream_id, 404, {}, nil)
    end
    local f, errinfo = io.open(filepath, 'rb')
    if not f then
      self:tolog(500, req['headers'][':path'], ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or ipaddr, req['headers'][':method'], now() - s)
      return error_response(sock, h2pack, stream_id, 500, {}, errinfo)
    end
    self:tolog(200, req['headers'][':path'], ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or ipaddr, req['headers'][':method'], now() - s)
    return normal_response(sock, h2pack, stream_id, 200, { ['content-disposition'] = 'attachment', ['content-type'] = 'application/octet-stream' }, f:read '*a'), f:close()
  end
  -- 开始处理注册`路由`
  local ok, info = pcall(cb, tab_copy(req), resp)
  if not ok then
    self:tolog(500, req['headers'][':path'], ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or ipaddr, req['headers'][':method'], now() - s)
    return error_response(sock, h2pack, stream_id, 500, resp.headers, info)
  end
  self:tolog(200, req['headers'][':path'], ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or ipaddr, req['headers'][':method'], now() - s)
  return normal_response(sock, h2pack, stream_id, toint(resp.code) or 200, resp.headers, resp.body)
end

local function url_decode(body)
  if type(body) ~= 'string' or body == '' then
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
local function request_builder(headers, bodys)
  local req = { headers = headers }
  local s = find(headers[":path"], '?')
  if s then
    req.args = url_decode(sub(headers[":path"], s + 1))
  end
  if headers[":method"] == "GET" or headers[":method"] == "POST" or headers[":method"] == "DELETE" or headers[":method"] == "PUT" then
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
  elseif headers[":method"] == "HEAD" or headers[":method"] == "OPTIONS" then
  end
  return req
end

local function DISPATCH(self, sock, opt)
  local sid = 1
  local h2pack = hpack:new(8192)
  local requests, priority = {}, {}
  if opt.req then
    h2_response(self, sock, sid, h2pack, opt, opt.req, {})
    opt.req = nil
  end
  while 1 do
    local head = read_head(sock)
    if not head then
      break
    end
    local tname = TYPE_TAB[head.type]
    -- print(tname)
    if tname == "SETTINGS" then
      if head.length > 0 then
        local _ = read_settings(sock, head)
        send_settings_ack(sock)
      end
    -- 自动回应`PING`
    elseif tname == "PING" then
      local info = read_ping(sock, head)
      local tab = FLAG_TO_TABLE(tname, head.flags)
      if not tab.ack then
        send_ping(sock, 0x01, info)
      end
    elseif tname == "GOAWAY" then
      local _ = read_goaway(sock, head)
      break
    elseif tname == "RST_STREAM" then
      local info = read_rstframe(sock, head)
      -- var_dump(info)
      break
    elseif tname == "PRIORITY" then
      -- 如果需要预留具有优先级流ID
      local tab = read_priority(sock, head)
      priority[tab.stream_id] = tab.weight
    elseif tname == "CONTINUATION" then
      -- 需要读取分割帧
      -- var_dump(head); var_dump(FLAG_TO_TABLE(tname, head.flags));
      local info = read_continuation(sock, head)
      if not info then
        break
      end
      local ctx = requests[head.stream_id]
      if not ctx then
        send_goaway(sock, ERRNO_TAB["PROTOCOL_ERROR"])
        break
      end
      -- `CONTINUATION`帧是`headers`的延伸.
      tinsert(ctx.headers, info)
    elseif tname == "WINDOW_UPDATE" then
      local window = read_window_update(sock, head)
      if not window then
        break
      end
      send_window_update(sock, window.window_size)
    -- 读取`HEADERS`帧或`DATA`帧
    elseif tname == "HEADERS" or tname == "DATA" then
      local tab = FLAG_TO_TABLE(tname, head.flags)
      local stream_id = head.stream_id
      if sid > stream_id then
        -- priority 帧有预留则保留此流ID, 否则当做协议错误处理
        if not priority[stream_id] then
          send_goaway(sock, ERRNO_TAB["PROTOCOL_ERROR"])
          break
        end
        -- 预留的sid需要被清除掉
        priority[stream_id] = nil
      end
      -- 获取请求流上下文.
      local ctx = requests[stream_id]
      if not ctx then
        ctx = { headers = {}, body = {} }
        requests[stream_id] = ctx
      end
      -- 读取内容
      if tname == "DATA" then
        tinsert(ctx.body, read_data(sock, head))
      elseif tname == "HEADERS" then
        tinsert(ctx.headers, read_headers(sock, head))
      end
      if tab.end_stream then
        sid = stream_id
        requests[stream_id] = nil
        -- print(crypt.hexencode(concat(ctx.headers)))
        local headers = h2pack:decode(concat(ctx.headers))
        if headers then
          h2_response(self, sock, stream_id, h2pack, opt, request_builder(headers, #ctx.body > 0 and concat(ctx.body) or nil), {})
        end
      end
    end
  end
  return sock:close()
end

local function HTTPD_DISPATCH(sock, opt, self)

  -- 检查握手
  local req = read_magic(sock)
  if not req then
    return sock:close()
  end

  -- SEND SETTINS
  send_settings(sock, nil, {
    -- SET TABLE SISZE
    -- {0x01, opt.SETTINGS_HEADER_TABLE_SIZE or SETTINGS_TAB["SETTINGS_HEADER_TABLE_SIZE"]},
    -- DISABLE PUSH
    {0x02, 0x00},
    -- SET CONCURRENT STREAM
    {0x03, 0x01},
    -- {0x03, SETTINGS_TAB["SETTINGS_MAX_CONCURRENT_STREAMS"]},
    -- SET WINDOWS SIZE
    {0x04, SETTINGS_TAB["SETTINGS_INITIAL_WINDOW_SIZE"]},
    -- SET MAX FRAME SIZE
    {0x05, SETTINGS_TAB["SETTINGS_MAX_FRAME_SIZE"]},
    -- SET SETTINGS MAX HEADER LIST SIZE
    {0x06, SETTINGS_TAB["SETTINGS_MAX_HEADER_LIST_SIZE"]},
  })
  -- 是否必须要发送呢?
  -- send_window_update(sock, 2 ^ 24 - 1)
  if type(req) == 'table' then
    opt.req = req
  end
  return DISPATCH(self, sock, opt)
end

return { HTTPD_DISPATCH = HTTPD_DISPATCH }