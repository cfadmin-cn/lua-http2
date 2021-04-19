local tcp = require "internal.TCP"

local hpack = require "lhpack"

local class = require "class"

local ua = require "protocol.http.ua"

local sys = require "sys"
local new_tab = sys.new_tab

local cf = require "cf"
local cfork = cf.fork

local h2_client = require "lua-http2.client"
local send_request = h2_client.send_request
local split_domain = h2_client.split_domain
local h2_handshake = h2_client.h2_handshake

local ipairs = ipairs
local os_time = os.time


local methods = { GET = true, POST = true}

local client = class("http2-client")

function client:ctor(opt)
  self.version = 0.1
  self.timeout = 10
  self.hpack = nil
  self.sock = nil
  self.connected = false
  self.domain = opt.domain
  self.sid = nil
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

---comment 发送`HTTP2`请求
---@param url string           @`http2`请求链接地址
---@param method string        @`http2`请求的方法
---@param headers table        @`http2`请求头部(`optional`)
---@param body string          @`http2`请求载荷(`optional`)
---@param timeout any          @`http2`请求超时(`optional`)
---@return nil|integer         @返回合法的`http`响应状态码`或者`nil`
---@return string|table        @返回合法的`http`响应头部或者出错信息
---@return string|nil          @返回合法的`http`响应数据载荷或者`nil`
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
  if type(headers) ~= 'table' and headers then
    return nil, "Invalid request headers."
  end
  local args
  if method == "GET" and type(body) == 'string' and body ~= '' then
    args = body
    body = nil
  end
  local info = self.info
  local h2pack = self.hpack
  local header = h2pack:encode(
    {
      [":method"] = method:upper(),
      [":scheme"] = info.scheme,
      [":authority"] = info.domain,
      [":path"] = url .. (args or ""),
    }
  ) .. h2pack:encode(
    {
      ["origin"] = info.domain,
      ["host"] = info.domain,
      ["accept"] = "*/*",
      ["accept-encoding"] = "gzip, deflate, identity",
      ["content-length"] = body and #body or nil,
      ["user-agent"] = ua.get_user_agent(),
    }
  ) .. h2pack:encode(headers or {})
  return send_request(self, header, body, timeout)
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