--[[
编写作者:

  Author: CandyMi[https://github.com/candymi]

编写日期:

  2020-11-06
]]

local log = require "logging"

local cf = require "cf"

local tcp = require "internal.TCP"

local hpack = require "lhpack"

-- local lz = require "lz"
-- local decompress = lz.compress
-- local gzcompress = lz.gzcompress

local url = require "url"
local urldecode = url.decode

local xml = require "xml2lua"
local xmlparse = xml.parser

local json = require "json"
local json_decode = json.decode

local aio = require "aio"
local aio_stat = aio.stat

local sys = require "sys"
local now = sys.now
local new_tab = sys.new_tab
local ipv4 = sys.ipv4
local ipv6 = sys.ipv6

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
local assert = assert
local tonumber = tonumber

local fmt = string.format
local sub = string.sub
local gsub = string.gsub
local find = string.find
local match = string.match
local gmatch = string.gmatch
local toint = math.tointeger
local concat = table.concat
local os_date = os.date
local tinsert = table.insert
local io_write = io.write

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
  local h = hpack:new(8192)
  local routes, foldor = self.routes, self.foldor
  local requests, priority = {}, {}
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
      local ctx = requests[head.stream_id]
      if ctx then
        -- `CONTINUATION`帧是`headers`的延伸.
        tinsert(ctx.headers, info)
      end
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
        local headers = h:decode(concat(ctx.headers))
        if headers then
          local req = request_builder(headers, #ctx.body > 0 and concat(ctx.body) or nil)
          -- var_dump(req)
          local resp = {}
          local path = urldecode(req['headers'][':path'] or '')
          path = gsub(sub(path, 1, (find(path, "?") or 0) - 1), '(/[/]+)', '/')
          -- 确认路由是否存在
          local cb = routes[path]
          if not cb then
            -- 是否需要检查静态文件
            local s = now()
            if not foldor then
              self:tolog(404, req['headers'][':path'], opt.ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or opt.ipaddr, req['headers'][':method'], now() - s)
              error_response(sock, h, stream_id, 404, {}, nil)
            else
              -- 检查静态文件
              if check_path(path) then
                self:tolog(404, req['headers'][':path'], opt.ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or opt.ipaddr, req['headers'][':method'], now() - s)
                error_response(sock, h, stream_id, 404, {}, nil)
              else
                local filepath = foldor .. path
                local stat = aio_stat(filepath)
                -- 检查是否合法
                if type(stat) ~= 'table' or stat.mode ~= 'file' then
                  self:tolog(404, req['headers'][':path'], opt.ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or opt.ipaddr, req['headers'][':method'], now() - s)
                  error_response(sock, h, stream_id, 404, {}, nil)
                else
                  local f = io.open(filepath, 'rb')
                  local body = f:read '*a'
                  f:close()
                  self:tolog(200, req['headers'][':path'], opt.ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or opt.ipaddr, req['headers'][':method'], now() - s)
                  normal_response(sock, h, stream_id, 200, { ['content-disposition'] = 'attachment', ['content-type'] = 'application/octet-stream' }, body)
                end
              end
            end
          else
            local s = now()
            local ok, info = pcall(cb, tab_copy(req), resp)
            if not ok then
              self:tolog(500, req['headers'][':path'], opt.ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or opt.ipaddr, req['headers'][':method'], now() - s)
              error_response(sock, h, stream_id, 500, resp.headers, info)
            else
              self:tolog(200, req['headers'][':path'], opt.ipaddr, req['headers']['X-Real-IP'] or req['headers']['X-real-ip'] or opt.ipaddr, req['headers'][':method'], now() - s)
              normal_response(sock, h, stream_id, toint(resp.code) or 200, resp.headers, resp.body)
            end
          end
        end
      end
    end
  end
  return sock:close()
end

local function RAW_DISPATCH(sock, opt, self)

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
  return DISPATCH(self, sock, opt)
end

local class = require "class"

local server = class("http2-server")

function server:ctor(opt)
  self.sock = tcp:new()
  self.routes = {}
end

---@comment Httpd2 路由方法注册
---@param prefix   string   @路由地址
---@param func function     @路由回调函数, 函数签名为: `function(req, resp)`, `req`是请求上下文, `resp`是响应上下文.
function server:route(prefix, func)
  assert(prefix:byte(1) == 47 and not find(prefix, "[ ]"), "[HTTPD2 ERROR] : Prefixes must begin with '/' and Spaces must not be allowed.")
  assert(not self.routes[prefix], "[HTTPD2 ERROR] : The registered routing method - `" .. tostring(prefix) .. "`.")
  self.routes[prefix] = func
end

---comment `httpd2`注册静态文件读取路径, `foldor`是一个目录, `ttl`是静态文件缓存周期
---@param foldor string @目录名称
---@param ttl number    @设置缓存时间
function server:static(foldor, ttl)
  if not self.foldor then
    self.foldor = foldor or 'static'
  end
end

---comment `httpd2`监听普通套接字与端口
---@param ip string        @需要监听的合法`IP`地址.
---@param port integer     @指定一个在有效范围内并未被占用的端口.
---@param backlog integer  @默认为`128`
function server:listen(ip, port, backlog)
  assert(type(ip) == 'string' and toint(port) and toint(port) > 0 and toint(port) < 65536, "http2d error: invalid ip or port")
  self.ip, self.port = (ipv4(ip) or ipv6(ip)) and ip or "0.0.0.0", port
  self.sock:set_backlog(toint(backlog) and toint(backlog) > 0 and toint(backlog) or 128)
  return assert(self.sock:listen(self.ip, self.port,
    function (fd, ipaddr, port)
      local sock = tcp:new()
      sock:set_fd(fd):timeout(self.__timeout or 15)
      return RAW_DISPATCH(sock, { ipaddr = match(ipaddr, '^::[f]+:(.+)') or ipaddr, port = port }, self)
    end)
  )
end

---comment LOG_FMT用于构建日志格式
local LOG_FMT = "[%s] - %s - %s - %s - %s - %d - req_time: %0.6f/Sec\n"

function server:tolog(code, path, ip, ip_list, method, speed)
  if self.CLOSE_LOG then
    return
  end
  local now = os_date("%Y/%m/%d %H:%M:%S")
  if self.logging then
    self.logging:dump(fmt(LOG_FMT, now, ip, ip_list, path, method, code, speed))
  end
  if io.type(io.output()) == 'file' then
    io_write(fmt(LOG_FMT, now, ip, ip_list, path, method, code, speed))
  end
end

---comment `httpd2`监听加密套接字与端口
---@param ip string       @需要监听的合法`IP`地址.
---@param port integer    @指定一个在有效范围内并未被占用的端口.
---@param backlog integer @默认为`128`, 这一般已经够用了.
---@param key string      @指定TLS套接字所需的私钥所在路径;
---@param cert string     @指定TLS套接字所需的证书所在路径;
---@param pw string       @如果证书和私钥设置的密码请填写此字段;
---@return boolean
function server:listen_ssl(ip, port, backlog, key, cert, pw)
  assert(type(ip) == 'string' and toint(port), "httpd error: invalid ip or port")
  self.ssl_ip, self.ssl_port = (ipv4(ip) or ipv6(ip)) and ip or "0.0.0.0", port
  self.ssl_key, self.ssl_cert, self.ssl_pw = key, cert, pw
  self.sock:set_backlog(toint(backlog) and toint(backlog) > 0 and toint(backlog) or 128)
  return assert(self.sock:listen_ssl(self.ssl_ip, self.ssl_port, { cert = self.ssl_cert, key = self.ssl_key, pw = self.ssl_pw },
    function (sock, ipaddr, port)
      return RAW_DISPATCH(sock, { ipaddr = match(ipaddr, '^::[f]+:(.+)') or ipaddr, port = port }, self)
    end)
  )
end

---comment 记录日志到文件
function server:log(path)
  if type(path) == 'string' and path ~= '' then
    self.logging = log:new({ dump = true, path = path })
  end
end

---comment 此方法应该在配置完成所有`httpd`配置后调用, 此方法之后的代码或将永远不会被执行.
function server:run()
  if self.ip and self.port then
    if self.logging then
      self.logging:dump(fmt('[%s] [INFO] h2 listen: %s:%s \n', os_date("%Y/%m/%d %H:%M:%S"), self.ip, self.port))
    end
    io_write(fmt('\27[32m[%s] [INFO]\27[0m h2 listen: %s:%s \n', os_date("%Y/%m/%d %H:%M:%S"), self.ip, self.port))
  end
  if self.logging then
    self.logging:dump(fmt('[%s] [INFO] h2 Web Server Running...\n', os_date("%Y/%m/%d %H:%M:%S")))
  end
  io_write(fmt('\27[32m[%s] [INFO]\27[0m h2 Web Server Running...\n', os_date("%Y/%m/%d %H:%M:%S")))
  return cf.wait()
end


return server