#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdio.h>

static const char script[] =
"local function sieve(n)\n"
"  local prime={} for i=2,n do prime[i]=true end\n"
"  for p=2,n do if prime[p] then local q=p*p if q<=n then for j=q,n,p do prime[j]=false end end end end\n"
"  local out={} for i=2,n do if prime[i] then out[#out+1]=tostring(i) end end\n"
"  local t={tag='primes', values=out}; collectgarbage('collect')\n"
"  return t.tag..':'..table.concat(t.values, ',')..';sum='..(function() local s=0 for i=1,#out do s=s+tonumber(out[i]) end return s end)()\n"
"end\n"
"print(sieve(50))\n";

int main(void) {
    lua_State *L = luaL_newstate();
    if (!L) return 2;
    luaL_openlibs(L);
    int status = luaL_loadbuffer(L, script, sizeof(script)-1, "embedded-sieve") ||
                 lua_pcall(L, 0, 0, 0);
    if (status) fprintf(stderr, "%s\n", lua_tostring(L, -1));
    lua_close(L);
    return status ? 1 : 0;
}
