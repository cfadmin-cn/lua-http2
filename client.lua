--[[
编写作者:

  Author: CandyMi[https://github.com/candymi]

编写日期:

  2020-11-06
]]

local http2 = require "protocol.http2.protocol"
local TYPE_TAB = http2.TYPE_TAB
local ERRNO_TAB = http2.ERRNO_TAB
local SETTINGS_TAB = http2.SETTINGS_TAB

local read_head = http2.read_head
local read_settings = http2.read_settings
local read_window_update = http2.read_window_update

local send_goaway = http2.send_goaway
local read_goaway = http2.read_goaway

local type = type
local pairs = pairs

local fmt = string.format

local client = { version = "0.1" }

function client.handshake(sock)

  sock.__timeout = 15

  -- SEND MAGIC BYTES
  http2.send_magic(sock)

  -- SEND SETTINS
  http2.send_settings(sock, nil, {
    -- SET TABLE SISZE
    {0x01, SETTINGS_TAB["SETTINGS_HEADER_TABLE_SIZE"]},
    -- ENABLE PUSH
    {0x02, SETTINGS_TAB["SETTINGS_ENABLE_PUSH"]},
    -- SET CONCURRENT STREAM
    {0x03, SETTINGS_TAB["SETTINGS_MAX_CONCURRENT_STREAMS"]},
    -- SET WINDOWS SIZE
    {0x04, SETTINGS_TAB["SETTINGS_INITIAL_WINDOW_SIZE"]},
    -- SET MAX FRAME SIZE
    {0x05, SETTINGS_TAB["SETTINGS_MAX_FRAME_SIZE"]},
    -- SET SETTINGS MAX HEADER LIST SIZE
    {0x06, SETTINGS_TAB["SETTINGS_MAX_HEADER_LIST_SIZE"]},
  })

  local settings

  while 1 do
    local head, err = read_head(sock)
    if not head then
      send_goaway(sock, ERRNO_TAB["SETTINGS_TIMEOUT"])
      return nil, err
    end
    local tname = TYPE_TAB[head.type]
    if not tname then
      send_goaway(sock, ERRNO_TAB["PROTOCOL_ERROR"])
      return nil, "Invalid `Frame Type` In handshake."
    end
    if tname == "SETTINGS" then
      if head.length == 0 then
        break
      end
      local s, errno = http2.read_settings(sock, head)
      if not s then
        send_goaway(sock, ERRNO_TAB[errno])
        return nil, "recv Invalid `SETTINGS` header."
      end
      settings = s
    end
    if tname == "WINDOW_UPDATE" then
      read_window_update(sock, head)
    end
    if tname == "GO_AWAY" then
      local info = read_goaway(sock, header)
      return nil, fmt("{ errcode = %d, errinfo = '%s'}", info.errno, info.errinfo)
    end
  end

  if type(settings) ~= 'table' then
    return nil, "Invalid Handshake"
  end

  http2.send_settings_ack(sock)

  for key, value in pairs(SETTINGS_TAB) do
    if type(key) == 'string' and not settings[key] then
      settings[key] = value
    end
  end

  settings['head'] = nil
  settings['ack'] = nil
  return settings
end


function client.connect(sock, domain, port)
  local ok, err = sock:connect(domain, port)
  if not ok then
    return nil, err
  end
  return client.handshake(sock)
end

function client.send_request(sock, ctx)
  -- body
end

function client.read_response(sock, ctx)
  -- body
end

return client