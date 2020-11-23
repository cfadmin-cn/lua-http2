--[[
编写作者:

  Author: CandyMi[https://github.com/candymi]

编写日期:

  2020-11-06
]]

local cf = require "cf"

local tcp = require "internal.TCP"

local hpack = require "lhpack"

local protocol = require "protocol.http2.protocol"
local read_magic = protocol.read_magic


local match = string.match
local toint = math.tointeger

local function DISPATCH(self, ipaddr)
  local sid = 1
  local sock = self.sock
  -- while 1 do

  -- end
  return sock:close()
end

local function RAW_DISPATCH(fd, ipaddr, self)
  local sock = tcp:new()
  sock:set_fd(fd):timeout(self.__timeout or 15)
  local ok, err = read_magic(sock)
  if not ok then
    return sock:close()
  end
  return DISPATCH(self, ipaddr)
end

local function SSL_DISPATCH(fd, ipaddr, self)
  local sock = tcp:new()
  sock:set_fd(fd):timeout(self.__timeout or 15)
  local ok, err = read_magic(sock)
  if not ok then
    return sock:close()
  end
  return DISPATCH(self, ipaddr)
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