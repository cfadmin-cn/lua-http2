#define LUA_LIB

#include <core.h>
#include "hpack.h"

// hpack 编码
static int lhpack_encode(lua_State *L) {
  struct cno_hpack_t *hpack = luaL_checkudata(L, 1, "__HPACK__");
  if (!hpack)
    return luaL_error(L, "[HPACK ENCODER]: Invalid hpack ctx.");

  luaL_checktype(L, 2, LUA_TTABLE);

  size_t n = 512;
  struct cno_header_t headers[n];
  // printf("1\n");
  size_t index = 0;
  lua_pushnil(L);
  while (lua_next(L, 2)) {
    size_t lname, lvalue;
    headers[index].flags = 0;
    headers[index].name.data  = lua_tolstring(L, -2, &lname);
    headers[index].name.size  = lname;
    headers[index].value.data  = lua_tolstring(L, -1, &lvalue);
    headers[index].value.size  = lvalue;
    lua_pop(L, 1);
    index++;
  }
  // printf("2\n");
  /* 如果是一个空表则返回空字符串 */
  if (!index) {
    lua_pushliteral(L, "");
    return 1;
  }

  struct cno_buffer_dyn_t hpack_buffer;
  memset(&hpack_buffer, 0x0, sizeof(struct cno_buffer_dyn_t));
  // printf("3\n");
  int ret = 0;
  if (CNO_OK != (ret = cno_hpack_encode(hpack, &hpack_buffer, headers, index))) {
    lua_pushnil(L);
    lua_pushfstring(L, "HPACK encode failed with error. code : [%d]", ret);
    return 2;
  }
  lua_pushlstring(L, hpack_buffer.data, hpack_buffer.size);
  cno_buffer_dyn_clear(&hpack_buffer);
  // printf("hpack_buffer = { size = [%ld], offset = [%ld], cap = [%ld]}\n", hpack_buffer.size, hpack_buffer.offset, hpack_buffer.cap);
  return 1;
}

// hpack 解码
static int lhpack_decode(lua_State *L) {
  struct cno_hpack_t *hpack = luaL_checkudata(L, 1, "__HPACK__");
  if (!hpack)
    return luaL_error(L, "[HPACK DECODER]: Invalid hpack ctx.");

  size_t bsize = 0;
  const char * buf = luaL_checklstring(L, 2, &bsize);
  if (!buf || bsize < 1)
    return luaL_error(L, "HPACK decode: Invalid string buffer.");
  
  lua_createtable(L, 64, 0);

  struct cno_buffer_t hpack_buffer = { .data = buf, .size = bsize };

  size_t n = 512;
  struct cno_header_t headers[n];

  int ret = 0;
  if (CNO_OK != (ret = cno_hpack_decode(hpack, hpack_buffer, headers, &n))) {
    lua_pushnil(L);
    lua_pushfstring(L, "HPACK decode failed with error. code : [%d]", ret);
    return 2;
  }

  size_t i;
  for (i = 0; i < n; i++) {
    // printf("index = [%ld], flags = [%d]\n", i, headers[i].flags);
    if (headers[i].name.data && headers[i].value.data){
      lua_pushlstring(L, headers[i].name.data, headers[i].name.size);
      lua_pushlstring(L, headers[i].value.data, headers[i].value.size);
      lua_rawset(L, -3);
    }
  }

  return 1;
}

// 垃圾回收
static int lhpack_gc(lua_State *L) {
  struct cno_hpack_t *hpack = luaL_checkudata(L, 1, "__HPACK__");
  if (hpack)
    cno_hpack_clear(hpack);
  return 0;
}

// 创建对象
static int lhpack_new(lua_State *L) {
  struct cno_hpack_t *hpack = lua_newuserdata(L, sizeof(struct cno_hpack_t));
  if (!hpack)
    return 0;
  int tsize = luaL_checkinteger(L, 2);
  if (tsize <= 0)
    tsize = 4096;
  // memset(hpack, 0x0, sizeof(struct cno_hpack_t));
  cno_hpack_init(hpack, tsize);
  luaL_setmetatable(L, "__HPACK__");
  return 1;
}

static inline void hpack_init(lua_State *L) {
  luaL_newmetatable(L, "__HPACK__");
  /* index meta table */
  lua_pushstring (L, "__index");
  lua_pushvalue(L, -2);
  lua_rawset(L, -3);
  /* week table */
  lua_pushliteral(L, "__mode");
  lua_pushliteral(L, "kv");
  lua_rawset(L, -3);

  /* base method */
  luaL_Reg hpack_libs[] ={
    {"encode", lhpack_encode},
    {"decode", lhpack_decode},
    {"__gc",   lhpack_gc},
    {NULL, NULL}
  };
  luaL_setfuncs(L, hpack_libs, 0);

  lua_newtable(L);
  /* new class */
  lua_pushliteral(L, "new");
  lua_pushcfunction(L, lhpack_new);
  lua_rawset(L, -3);
  /* set version */
  lua_pushliteral(L, "http2_version");
  lua_pushliteral(L, "0.1");
  lua_rawset(L, -3);
}

LUAMOD_API int luaopen_lhpack(lua_State *L) {
  luaL_checkversion(L);
  hpack_init(L);
  return 1;
}
