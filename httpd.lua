local log = require "logging"

local cf = require "cf"

local tcp = require "internal.TCP"

local http2_server = require "lua-http2.server"
local HTTPD_DISPATCH = http2_server.HTTPD_DISPATCH

local sys = require "sys"
local ipv4 = sys.ipv4
local ipv6 = sys.ipv6


local type = type
local assert = assert

local fmt = string.format
local find = string.find
local match = string.match
local toint = math.tointeger
local os_date = os.date
local io_write = io.write


local class = require "class"

local server = class("http2-server")

function server:ctor(opt)
  self.sock = tcp:new()
  self.routes = {}
end

---@comment `Httpd2`路由方法注册
---@param prefix string    @路由地址
---@param func   function  @路由回调函数, 函数签名为: `function(req, resp)`, `req`是请求上下文, `resp`是响应上下文.
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
      return HTTPD_DISPATCH(sock, { ipaddr = match(ipaddr, '^::[f]+:(.+)') or ipaddr, port = port }, self)
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
      return HTTPD_DISPATCH(sock, { ipaddr = match(ipaddr, '^::[f]+:(.+)') or ipaddr, port = port }, self)
    end)
  )
end

---comment 记录日志到文件
function server:log(path)
  if type(path) == 'string' and path ~= '' then
    self.logging = log:new({ dump = true, path = path })
  end
end

---comment 关闭日志记录
function server:nolog()
  self.CLOSE_LOG = true
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