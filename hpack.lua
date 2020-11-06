--[[

参考文档:

  * RFC 7541 - HPACK: Header Compression for HTTP/2 - https://www.rfc-editor.org/rfc/rfc7541.txt

  * 中译版 - https://github.com/halfrost/Halfrost-Field/blob/master/contents/Protocol/HTTP:2_Header-Compression.md

授权协议:

  LICENSE: MIT

编写作者:

  Author: CandyMi[https://github.com/candymi]

编写日期:

  2020-11-06

]]

local assert = assert

local class = require "class"

local hpack = class("hpack")

function hpack:ctor(...)
	self.tab = nil
end

function hpack:encode(list)
	assert(nil, "need implement `encode` method .")
end

function hpack:decode(list)
	assert(nil, "need implement `decode` method .")
end

return hpack