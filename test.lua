require "utils"

local cf = require "cf"


local client = require "protocol.http2.client"

local h2 = client:new {
  -- domain = "http://localhost"
  domain = "http://nghttp2.org/"
  -- domain = "https://www.taobao.com/"
  -- domain = "http://www.jd.com/"
}

local opt, err = h2:connect()
if not opt then
  return print(opt, err)
end

local body

require "cf".fork(function ( ... )
  local response, err = h2:request("/", "GET", {
    ["te"] = "trailers",
    ["content-type"] = "application/grpc",
    ["grpc-accept-encoding"] = "gzip, identity"
  }, body, 0.2)

  if not response then
    return print(err)
  end
  var_dump(response)
end)

cf.fork(function ( ... )
  local response, err = h2:request("/", "GET", {
    ["te"] = "trailers",
    ["content-type"] = "application/grpc",
    ["grpc-accept-encoding"] = "gzip, identity"
  }, body, 0.2)

  if not response then
    return print(err)
  end
  var_dump(response)
end)

cf.fork(function ( ... )
  local response, err = h2:request("/", "GET", {
    ["te"] = "trailers",
    ["content-type"] = "application/grpc",
    ["grpc-accept-encoding"] = "gzip, identity"
  }, body, 15)

  if not response then
    return print(err)
  end
  var_dump(response.headers)
  print(#response.body)
end)