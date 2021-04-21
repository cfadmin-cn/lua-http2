--[[

参考文档:

  * RFC 7541 - HPACK: Header Compression for HTTP/2 - https://www.rfc-editor.org/rfc/rfc7541.txt

  * 中译版 - https://github.com/halfrost/Halfrost-Field/blob/master/contents/Protocol/HTTP:2_Header-Compression.md

授权协议:

  LICENSE: MIT

编写作者:

  Author: CandyMi[https://github.com/candymi]

依赖项目地址:

  内置已经有一份`hpack`实现, 但是您可以选择使用 https://github.com/CandyMi/lhpack)(nghttp2-hpack).

编写日期:

  2020-11-06

]]

return require "lhpack"