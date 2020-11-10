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
local flag_to_table = http2.flag_to_table

local read_head = http2.read_head
local read_data = http2.read_data

local send_magic = http2.send_magic

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
local pairs = pairs

local fmt = string.format
local toint = math.tointeger

-- 必须遵守此stream id递增规则
local function new_stream_id(num)
  if not toint(num) or num < 1 then
    return 1
  end
  return (num + 2) & 2147483647
end

local client = { version = "0.1", timeout = 5 }

function client.handshake(sock, opt)

  -- 指定握手超时时间
  sock._timeout = client.timeout

  -- SEND MAGIC BYTES
  send_magic(sock)

  -- SEND SETTINS
  send_settings(sock, nil, {
    -- SET TABLE SISZE
    -- {0x01, opt.SETTINGS_HEADER_TABLE_SIZE or SETTINGS_TAB["SETTINGS_HEADER_TABLE_SIZE"]},
    -- ENABLE PUSH
    -- {0x02, opt.SETTINGS_ENABLE_PUSH or SETTINGS_TAB["SETTINGS_ENABLE_PUSH"]},
    {0x02, 0x00},
    -- SET CONCURRENT STREAM
    {0x03, opt.SETTINGS_MAX_CONCURRENT_STREAMS or SETTINGS_TAB["SETTINGS_MAX_CONCURRENT_STREAMS"]},
    -- SET WINDOWS SIZE
    {0x04, 1073741821 or opt.SETTINGS_INITIAL_WINDOW_SIZE or SETTINGS_TAB["SETTINGS_INITIAL_WINDOW_SIZE"]},
    -- SET MAX FRAME SIZE
    -- {0x05, opt.SETTINGS_MAX_FRAME_SIZE or SETTINGS_TAB["SETTINGS_MAX_FRAME_SIZE"]},
    -- SET SETTINGS MAX HEADER LIST SIZE
    -- {0x06, opt.SETTINGS_MAX_HEADER_LIST_SIZE or SETTINGS_TAB["SETTINGS_MAX_HEADER_LIST_SIZE"]},
  })

  send_window_update(sock, 2 ^ 24 - 1)

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

function client.close(sock)
  return send_goaway(sock, 0x00) and sock:close()
end


function client.connect(sock, opt)
  local ok, err = sock:connect(opt.host, opt.port)
  if not ok then
    return nil, err
  end
  return client.handshake(sock, opt)
end

function client.send_request(ctx)
  local sock = ctx.sock
  local sid = new_stream_id(ctx.sid)
  -- return send_headers(sock, 0x05, sid, ctx.hpack:encode(ctx.headers)) and send_settings_ack(sock) and sid or false
  send_headers(sock, 0x05, sid, ctx.hpack:encode(ctx.headers))
  -- send_settings_ack(sock)
  return sid
  -- send_settings_ack(sock)
end

function client.dispatch_all(ctx)
  local headers, body
  local sock = ctx.sock
  local waits = ctx.waits
  local response
  while 1 do
    local head, err = read_head(sock)
    if not head then
      send_goaway(sock, ERRNO_TAB["SETTINGS_TIMEOUT"])
      return nil, err
    end
    local tname = TYPE_TAB[head.type]
    if tname == "GOAWAY" then
      local info = read_goaway(sock, head)
      error(fmt("{errcode = %d, errinfo = '%s'%s}", info.errcode, info.errinfo, info.trace and ', trace = ' .. info.trace or ''))
    end
    if tname == "RST_STREAM" then
      local info = read_rstframe(sock, head)
      error(fmt("{ errcode = %d, errinfo = '%s'}", info.errcode, info.errinfo))
    end
    if tname == "HEADERS" then
      local header_bytes, err = read_headers(sock, head)
      if not header_bytes then
        return nil, err
      end
      headers = ctx.hpack:decode(header_bytes)
    end
    if tname == "DATA" then

      local tab = flag_to_table("DATA", head.flags)
      if not response then
        if tab.end_stream then
          return { headers = headers, body = read_data(sock, head) }
        end
        response = new_tab(32, 0)
      end
      response[#response+1] = read_data(sock, head)
      if tab.end_stream then
        local body = concat(response)
        response = nil
        return { headers = headers, body = body }
      end
    end
  end
  return true
end

return client