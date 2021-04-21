# http2

  Http2 library implemented in lua language.

## Introduction

  High performance 'HTTP2' protocol 'server' and 'client' library based on [cfadmin](https://cfadmin.cn/).

## Api - Http2 Client

  using `local httpc = require "lua-http2.httpc"`.

### 1. `function httpc:new(opt) httpc-class end`

  Use the `new` method creates an `httpc request object`.

### 2. `function httpc:connect() boolean end`

  Use the `connect` method of the `httpc` object to connect to the server; return `true` for success, return `false` and `string` for failure.

### 3. `function httpc:request(url, method, headers, args, timeout) response end`

  Use the `request` method of the `httpc` object to request Server.

  * `url` - http2 `path`. (e.g `/api`);

  * `method` - http2 `method`. (e.g `GET`、`POST`);

  * `headers` - http2 headers. (e.g `{["content-type"] = "application/json"}`)

  * `body|args` - http2 args or body. (e.g `table = {{"a",1}, {"b",2}}`、`"a=1&b=2"`、`"{}"`)

  * `timeout` - request timeout. (timeout `MUST` > 0)

## Api - Http2 Server

  using `local httpd = require "lua-http2.httpd"`.

### 1. `function httpd:new(opt) httpd-class end`

  Use the `new` method creates an `httpd server object`.

### 2. `function httpd:route(path, callback(req, resp)) end`

  Use the `route` method to register an `http2` route callback.

  `req` - is the request context of the client.

  `resp` - can include 'response content' and 'response header'`.

### 3. `function httpd:static(folder) end`

  Specify the `folder` parameter as the static file lookup directory.

### 4. `function httpd:listen(ip, port) end`

  Start listening to the specified `IP` and `Port`.

### 5. `function httpd:log(filepath) end`

  Write the request log to the file specified in `filepath`.

### 6. `function httpd:nolog() end`

  Turn off `print` and `write` any request records.

### 7. `function httpd:run() end`

  All code after this method is not executed.

## Code sample

  Next, we will introduce the examples and use methods of 'client' and 'server' respectively.

### Server

<details>
  <summary>Server code example</summary>

```lua
require "utils"

local httpd = require "lua-http2.httpd"

local h2 = httpd:new()

-- 注册路由
h2:route("/", function (req, resp)
  var_dump(req)
  resp['body'] = "Loging."
end)

-- 静态文件路由
h2:static("static")

-- -- 关闭请求日志
-- h2:nolog()

h2:listen("localhost", 80)

h2:run()
```

```bash
[candy@MacBookPro:~/Documents/cfadmin] $ ./cfadmin
[2021/04/19 20:24:19] [INFO] h2 listen: 0.0.0.0:80
[2021/04/19 20:24:19] [INFO] h2 Web Server Running...
{
      ["headers"] = {
            ["host"] = "127.0.0.1",
            [":scheme"] = "http",
            ["origin"] = "127.0.0.1",
            ["accept"] = "*/*",
            ["user-agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36",
            [":path"] = "/",
            [":authority"] = "127.0.0.1",
            [":method"] = "GET",
            ["accept-encoding"] = "gzip, deflate, identity",
      },
}
[2021/04/19 20:24:28] - 127.0.0.1 - 127.0.0.1 - / - GET - 200 - req_time: 0.000029/Sec
```
</details>


### Client

<details>
  <summary>Client code example</summary>

```lua
require "utils"

local httpc = require "lua-http2.httpc"

-- 创建对象
local hc = httpc:new { domain = "http://127.0.0.1/" }

-- 连接到服务器
if not hc:connect() then
  return print("连接失败")
end

-- 发送请求
local opt, errinfo = hc:request("/", "GET")
if not opt then
  return print(false, errinfo)
end

var_dump(opt)
```

```bash
[candy@MacBookPro:~/Documents/cfadmin] $ ./cfadmin
{
      ["headers"] = {
            ["content-type"] = "text/html; charset=utf-8",
            ["server"] = "cfadmin/0.1",
            ["date"] = "Mon, 19 Apr 2021 20:24:28 GMT",
            [":status"] = "200",
      },
      ["body"] = "Loging.",
}
```

</details>