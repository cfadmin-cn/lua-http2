local crypt = require "crypt"
--[[

参考文档:

  * RFC 7540 - Hypertext Transfer Protocol Version 2 (HTTP/2) - https://www.rfc-editor.org/rfc/inline-errata/rfc7540.html

  * 中译版 - https://github.com/abbshr/rfc7540-translation-zh_cn

授权协议:

  LICENSE: MIT

编写作者:

  Author: CandyMi[https://github.com/candymi]

编写日期:

  2020-11-06

]]

local sys = require "sys"
local new_tab = sys.new_tab

local type = type
local pcall = pcall
local ipairs = ipairs
local assert = assert

local concat = table.concat
local toint = math.tointeger
local strpack = string.pack
local strunpack = string.unpack

local empty_table = {}

local ONLY_HTTP_1_1 = { version = 1.1 }

-- HTTP2 MAGIC :
local MAGIC = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
-- local MAGIC = "\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a"

local Upgrade = "h2c"
local Connection = "Upgrade, HTTP2-Settings"
local protocol_switch = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"

-- HTTP2帧类型对照表
local TYPE_TAB = {
  [0x00] = "DATA",
  [0x01] = "HEADERS",
  [0x02] = "PRIORITY",
  [0x03] = "RST_STREAM",
  [0x04] = "SETTINGS",
  [0x05] = "PUSH_PROMISE",
  [0x06] = "PING",
  [0x07] = "GOAWAY",
  [0x08] = "WINDOW_UPDATE",
  [0x09] = "CONTINUATION",

  ["DATA"]           = 0x00,
  ["HEADERS"]        = 0x01,
  ["PRIORITY"]       = 0x02,
  ["RST_STREAM"]     = 0x03,
  ["SETTINGS"]       = 0x04,
  ["PUSH_PROMISE"]   = 0x05,
  ["PING"]           = 0x06,
  ["GOAWAY"]         = 0x07,
  ["WINDOW_UPDATE"]  = 0x08,
  ["CONTINUATION"]   = 0x09,
}

local FLAGS_TRANSFER_TAB = {
	[0x00] = function (flags)
		return {
			end_stream = flags & 0x01 == 0x01 and true,
			padded = flags & 0x08 == 0x08 and true,
		}
	end,
	[0x01] = function (flags)
		return {
			end_stream = flags & 0x01 == 0x01 and true or false,
			end_headers = flags & 0x04 == 0x04 and true or false,
			padded = flags & 0x08 == 0x08 and true or false,
			prioroty = flags & 0x20 == 0x20 and true or false,
		}
	end,
	[0x02] = function (flags)
		return empty_table
	end,
	[0x03] = function (flags)
		return empty_table
	end,
	[0x04] = function (flags)
		return { ack = flags == 0x01 and true or false }
	end,
	[0x05] = function (flags)
		return {
			end_headers = flags & 0x04 == 0x04 and true or false,
			padded = flags & 0x08 == 0x08 and true or false,
		}
	end,
	[0x06] = function (flags)
		return { ack = flags == 0x01 and true or false }
	end,
	[0x07] = function (flags)
		return empty_table
	end,
	[0x08] = function (flags)
		return empty_table -- All reserved
	end,
	[0x09] = function (flags)
		return { end_headers = flags & 0x04 == 0x04 or false }
	end,
}

local SETTINGS_TAB = {
	["SETTINGS_HEADER_TABLE_SIZE"] = 8192,
	["SETTINGS_ENABLE_PUSH"] = 1,
	["SETTINGS_MAX_CONCURRENT_STREAMS"] = 100,
	["SETTINGS_INITIAL_WINDOW_SIZE"] = 2^24 - 1,
	["SETTINGS_MAX_FRAME_SIZE"] = 2^24 - 1,
	["SETTINGS_MAX_HEADER_LIST_SIZE"] = 8192,

	[0x01] = "SETTINGS_HEADER_TABLE_SIZE",      -- 允许发送者通知远端，用于解码首部块的首部压缩表的最大大小(以字节为单位): 初始值是4096字节;
	[0x02] = "SETTINGS_ENABLE_PUSH",            -- 这个设置项可被用于禁用服务端推送： 1为允许服务端推送, 0为不允许;
	[0x03] = "SETTINGS_MAX_CONCURRENT_STREAMS", -- 指明了发送者允许的最大的并发流个数。这个限制是有方向的：它应用于发送者允许接收者创建的流的个数;
	[0x04] = "SETTINGS_INITIAL_WINDOW_SIZE",    -- 指明了发送者stream-level flow control的初始窗口大小(以字节为单位): 2^16 ~ 2^31 - 1;
	[0x05] = "SETTINGS_MAX_FRAME_SIZE",         -- 指明了发送者期望接收的最大的帧载荷大小(以字节为单位): 2^14 ~ 2^24 - 1;
	[0x06] = "SETTINGS_MAX_HEADER_LIST_SIZE",   -- 这个建议性的设置通知对端发送者准备接受的首部列表的最大大小(以字节为单位);
}

-- HTTP2错误类型对照表
local ERRNO_TAB = {
  [0x00] = "NO_ERROR",
  [0x01] = "PROTOCOL_ERROR",
  [0x02] = "INTERNAL_ERROR",
  [0x03] = "FLOW_CONTROL_ERROR",
  [0x04] = "SETTINGS_TIMEOUT",
  [0x05] = "STREAM_CLOSED",
  [0x06] = "FRAME_SIZE_ERROR",
  [0x07] = "REFUSED_STREAM",
  [0x08] = "CANCEL",
  [0x09] = "COMPRESSION_ERROR",
  [0x0A] = "CONNECT_ERROR",
  [0x0B] = "ENHANCE_YOUR_CALM",
  [0x0C] = "INADEQUATE_SECURITY",
  [0x0D] = "HTTP_1_1_REQUIRED",

  ["NO_ERROR"]             = 0x00,
  ["PROTOCOL_ERROR"]       = 0x01,
  ["INTERNAL_ERROR"]       = 0x02,
  ["FLOW_CONTROL_ERROR"]   = 0x03,
  ["SETTINGS_TIMEOUT"]     = 0x04,
  ["STREAM_CLOSED"]        = 0x05,
  ["FRAME_SIZE_ERROR"]     = 0x06,
  ["REFUSED_STREAM"]       = 0x07,
  ["CANCEL"]               = 0x08,
  ["COMPRESSION_ERROR"]    = 0x09,
  ["CONNECT_ERROR"]        = 0x0A,
  ["ENHANCE_YOUR_CALM"]    = 0x0B,
  ["INADEQUATE_SECURITY"]  = 0x0C,
  ["HTTP_1_1_REQUIRED"]    = 0x0D,
}

--[[

+----------------------------------------------------------------+
|                 Length (24)           |  Type (8) |  Flags (8) |
+-+-------------+-----------------------+------------------------+
|R|                    Stream Identifier (31)                    |
+-+-------------+-----------------------+------------------------+
|                        Frame Payload ...                       |
+----------------------------------------------------------------+

Length : 代表整个 frame 的长度，用一个 24 位无符号整数表示;(但是这不意味着就能处理 2^24 16M大小的帧，一般是默认只支持2^16 16k以下的帧，而2^16 - 2^24 16M 的帧 需要接收端公布自己可以处理这么大的帧，需要在 SETTINGS_MAX_FRAME_SIZE 帧中告知)

Type : HTTP2帧类型, 未知的帧类型应该忽略或抛弃;

Flags : 是为帧类型相关而预留的布尔标识, 表示对于不同的帧类型赋予了不同的语义;

R: 是一个保留的比特位。这个比特的语义没有定义，发送时它必须被设置为 (0x0), 接收时需要忽略;

Stream Identifier: 流标识符表示为一个无符号的31位整数。值0x0保留给与整个连接相关联的帧，而不是单个流;

Frame Payload : 是帧主体内容由帧类型决定;

]]

local function sock_read(sock, bytes)
	local buffers = new_tab(16, 0)
	while 1 do
		local buffer, err = sock:recv(bytes)
    if not buffer then
      return nil, err
    end
		buffers[#buffers+1] = buffer
		if bytes <= #buffer then
			break
		end
		bytes = bytes - #buffer
	end
	return concat(buffers)
end

local function sock_write(sock, data)
	return sock:send(data)
end

-- 判断帧类型
local function is_frame(fname, fcode)
	return fname == TYPE_TAB[fcode]
end

-- 帧标志位转换为table
local function flag_to_table(fname, flags)
	local fcode = TYPE_TAB[fname]
	if not fcode then
		return
	end
	local convert = FLAGS_TRANSFER_TAB[fcode]
	if not convert then
		return
	end
	return convert(flags)
end

-- 读取通用包头部
local function read_head(sock)
  local head = sock_read(sock, 9)
  if not head then
    return nil, "The peer closed the connection during receiving `head` data."
  end
  local length, t, flags, bit = strunpack(">I3BBI4", head)
  if head == "HTTP/1.1 " or t > #TYPE_TAB then
    -- print(require "crypt".hexencode(head), length, t, flags, bit)
    return ONLY_HTTP_1_1
  end
  return { length = length, type = t, type_name = TYPE_TAB[t], flags = flags, reserved = bit >> 31, stream_id = bit & 2147483647 }
end

local function send_head(sock, length, tp, flags, sid)
  return sock_write(sock, strpack(">I3BBI4", length, tp, flags, sid))
end

local function send_body(sock, body)
  return sock_write(sock, body)
end

-- 读取magic包
local function read_magic(sock)
	local msg1 = sock_read(sock, #MAGIC)
	if msg1 == MAGIC then
		return true
	end
	local msg2 = sock:readline("\r\n\r\n")
	if not msg2 then
		return false, "the session's socket timeout or connection closed."
	end
	local h1_req, headers = msg1 .. msg2, {}
	for line in h1_req:gmatch("([^\r\n]+)") do
		for key, value in line:gmatch("([^ :]+)[ ]*:[ ]*(.+)") do
			if key and value and key ~= '' and value ~= '' then
				headers[key:lower()] = value
			end
		end
	end
	-- var_dump(headers)
	local ok, payload = pcall(crypt.base64urldecode, headers['http2-settings'])
	if not ok then
		return false, "Http Upgrade failed, need valid `http-settings`."
	end
	local settings = { }
	for pos = 1, #payload, 6 do
		local k, v = strunpack(">I2I4", payload, pos)
		local key = SETTINGS_TAB[k]
		if key then
			settings[key] = v
		end
	end
	-- var_dump(settings)
	-- 检查是否有`升级协议`.
	if (headers['upgrade'] ~= Upgrade) or (headers['connection'] ~= Connection) or not next(settings) then
		return false, "Http Upgrade failed."
	end
	headers[':method'], headers[':path'] = h1_req:match("([^ ]+) ([^ ]+) HTTP/1.1")
	-- var_dump(headers)
	-- 回应`协议升级`
	if not sock_write(sock, protocol_switch) then
		return false
	end
	local body = nil
	-- 需要注意的是:客户端支持的升级协议也可能携带`body`.
	local content_length = toint(headers['content-length'])
	if content_length and content_length > 0 then
		body = sock_read(sock, content_length)
		if not body then
			return false
		end
	end
	-- 再次检查是否发送`MAGIC`
	if sock_read(sock, #MAGIC) ~= MAGIC then
		return false
	end
	-- print("升级成功.")
	-- var_dump({ headers = headers, body = body })
	return { headers = headers, body = body }
end

local function send_magic(sock)
  return sock_write(sock, MAGIC)
end

-- 读取DATA包内容
local function read_data(sock, head)
	if not head then
		local err
		head, err = read_head(sock)
		if not head then
			return nil, err
		end
	end
	assert(head.type == TYPE_TAB["DATA"], "Invalid `data` packet.")
	return sock_read(sock, head.length)
end

-- 发送DATA包内容
local function send_data(sock, flags, stream_id, payload)
  return send_head(sock, #payload, TYPE_TAB["DATA"], flags or 0x01, stream_id) and send_body(sock, payload)
end

-- 读取HEADERS包内容
local function read_headers(sock, head)
	if not head then
		local err
		head, err = read_head(sock)
		if not head then
			return nil, err
		end
	end
	assert(head.type == TYPE_TAB["HEADERS"], "Invalid `headers` packet.")
	local len = 0
	-- 需要忽略`PRIORITY`包携带的特殊数据.
	if flag_to_table(head.type_name, head.flags).prioroty then
		len = 5
		sock_read(sock, len)
	end
	return sock_read(sock, head.length - len)
end

-- 发送HEADERS包
local function send_headers(sock, flags, stream_id, payload)
  return send_head(sock, #payload, TYPE_TAB["HEADERS"], flags or 0x05, stream_id) and send_body(sock, payload)
end

-- 读取SETTINGS包内容
local function read_settings(sock, head)
	if not head then
		local err
		head, err = read_head(sock)
		if not head then
			return nil, err
		end
	end
	assert(head.type == TYPE_TAB["SETTINGS"], "Invalid `settings` packet.")
	if head.flags == 0x01 and head.length ~= 0 then -- 规范强制要求
		return nil, ERRNO_TAB[ERRNO_TAB["FRAME_SIZE_ERROR"]]
	end
	if head.stream_id ~= 0 then -- 规范强制要求
		return nil, ERRNO_TAB[ERRNO_TAB["PROTOCOL_ERROR"]]
	end
	local settings = { head = head, ack = head.flags & 0x01 == 0x01 }
	for _ = 1, head.length // 6, 1 do
		local packet = sock_read(sock, 6)
		if not packet then
			return nil, "The peer closed the connection while receiving `settings` payload."
		end
		local k, v = strunpack(">I2I4", packet)
		local key = SETTINGS_TAB[k]
		if key then
			settings[key] = v
		end
	end
	return settings
end

-- 发送SETTINGS包
local function send_settings(sock, flags, settings)
  local payload = ""
  if type(settings) == 'table' and #settings > 0 then
    local payloads = new_tab(#settings, 0)
    for _, item in ipairs(settings) do
      -- print(item[1], item[2])
      payloads[#payloads+1] = strpack(">I2I4", item[1], item[2])
    end
    payload = concat(payloads)
  end
  return send_head(sock, #payload, TYPE_TAB["SETTINGS"], flags or 0x00, 0x00) and send_body(sock, payload)
end

local function send_settings_ack(sock)
  return send_settings(sock, 0x01)
end

-- 读取GOAWAY包内容
local function read_goaway(sock, head)
	if not head then
		local err
		head, err = read_head(sock)
		if not head then
			return nil, err
		end
	end
	assert(head.type == TYPE_TAB["GOAWAY"], "Invalid `goaway` packet.")
	local packet = sock_read(sock, 8)
	if not packet then
		return nil, "The peer closed the connection while receiving `goaway` payload."
	end
  local trace
  local promised, errcode = strunpack(">I4", packet)
  if head.length > 8 then
    trace = sock_read(sock, head.length - 8)
  end
	return {
		errcode = errcode,
		errinfo = ERRNO_TAB[errcode],
		promised_reserved = promised >> 31,
		promised_stream_id = promised & 0x7FFFFFFF,
		head = head,
		trace = trace,
	}
end

-- 发送`GOAWAY`包
local function send_goaway(sock, errno)
  return send_head(sock, 8, 0x07, 0x00, 0x00) and send_body(sock, strpack(">I4I4", 0x00, errno or 0x00))
end

-- 读取`WINDOW_UPDATE`包
local function read_window_update(sock, head)
	if not head then
		local err
		head, err = read_head(sock)
		if not head then
			return nil, err
		end
	end
	assert(head.type == TYPE_TAB["WINDOW_UPDATE"], "Invalid `window_update` packet.")
	local len = head.length
	if not len or len ~= 4 then
		return {}
	end
	local packet = sock_read(sock, 4)
	if not packet then
		return nil, "The peer closed the connection while receiving `window_update` payload."
	end
	local bit = strunpack(">I4", packet)
	return {
		head = head,
		reserved = bit >> 31,             -- 记录高1位
		window_size = bit & 2^31 - 1,     -- 记录低31位
	}
end

-- 发送`WINDOW_UPDATE`包
local function send_window_update(sock, window_size)
	return send_head(sock, 4, TYPE_TAB["WINDOW_UPDATE"], 0x00, 0x00) and send_body(sock, strpack(">I4", window_size or (1 << 24)))
end

-- 读取RST_STREAM包
local function read_rstframe(sock, head)
	if not head then
		local err
		head, err = read_head(sock)
		if not head then
			return nil, err
		end
	end
	assert(head.type == TYPE_TAB["RST_STREAM"], "Invalid `RST_STREAM` packet.")
	local packet = sock_read(sock, head.length)
	local errcode = strunpack(">I4", packet)
	return { head = head, errcode = errcode, errinfo = ERRNO_TAB[errcode] }
end

-- 发送`RST_STREAM`包
local function send_rstframe(sock, stream_id, errno)
	return send_head(sock, 4, TYPE_TAB["RST_STREAM"], 0x00, stream_id) and send_body(sock, strpack(">I4", errno or ERRNO_TAB["NO_ERROR"]))
end

local function read_ping(sock, head)
  if not head then
    local err
    head, err = read_head(sock)
    if not head then
      return nil, err
    end
  end
  assert(head.type == TYPE_TAB["PING"], "Invalid `PING` packet.")
  return sock_read(sock, 8)
end

local function send_ping(sock, flags, payload)
  return send_head(sock, #payload, TYPE_TAB["PING"], flags, 0) and send_body(sock, payload)
end

-- 读取`PROMISE`帧
local function read_promise(sock, head)
	if not head then
		local err
		head, err = read_head(sock)
		if not head then
			return nil, err
		end
	end
	assert(head.type == TYPE_TAB["PUSH_PROMISE"], "Invalid `PUSH_PROMISE` packet.")
	local packet = sock_read(sock, 4)
	if not packet then
		return nil, "The peer closed the connection while receiving `PUSH_PROMISE` payload."
	end
	local bit = strunpack(">I4", packet)
	local headers_byte
  if head.length - 4 > 0 then
    headers_byte = sock_read(sock, head.length - 4)
  end
	return bit & 2^31 - 1, headers_byte
end

-- 读取`PRIORITY`帧
local function read_priority(sock, head)
	if not head then
		local err
		head, err = read_head(sock)
		if not head then
			return nil, err
		end
	end
	assert(head.type == TYPE_TAB["PRIORITY"], "Invalid `PRIORITY` packet.")
	if not sock_read(sock, 4) then
		return nil, "The peer closed the connection while receiving `PRIORITY` payload. 1"
	end
	local pack = sock_read(sock, 1)
	if not pack then
		return nil, "The peer closed the connection while receiving `PRIORITY` payload. 2"
	end
	return { stream_id = head.stream_id, weight = strunpack("B", pack) + 1}
end

local function read_continuation (sock, head)
	if not head then
		local err
		head, err = read_head(sock)
		if not head then
			return nil, err
		end
	end
	assert(head.type == TYPE_TAB["CONTINUATION"], "Invalid `CONTINUATION` packet.")
	return sock_read(sock, head.length)
end

return {
	version = "0.1",
	-- 标准编码表
	MAGIC = MAGIC,
	TYPE_TAB = TYPE_TAB,
	ERRNO_TAB = ERRNO_TAB,
	SETTINGS_TAB = SETTINGS_TAB,
	FLAGS_TRANSFER_TAB = FLAGS_TRANSFER_TAB,
	-- 判断与转换方法
	is_frame = is_frame,
	flag_to_table = flag_to_table,

	-- 读取协议头部
	read_head = read_head,

  read_ping = read_ping,
  send_ping = send_ping,

	read_data = read_data,
  send_data = send_data,

  read_magic = read_magic,
  send_magic = send_magic,

	read_window_update = read_window_update,
	send_window_update = send_window_update,

	read_priority = read_priority,

	read_promise = read_promise,

	read_continuation = read_continuation,

  read_settings = read_settings,
	send_settings = send_settings,
	send_settings_ack = send_settings_ack,

	send_headers = send_headers,
	read_headers = read_headers,

  read_goaway = read_goaway,
  send_goaway = send_goaway,

  read_rstframe = read_rstframe,
  send_rstframe = send_rstframe,
}

