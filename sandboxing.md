# Sandboxing
In lua, you may want to intercept acess to parts of the language. With `loadstring`, users can execute any code they want.
This is where we introduce **sandboxing**.
The most practical use for sandboxing, is script builders.
Let's say you have a script builder, and you don't want someone to be able to destroy a player. Well, the easiest thing to do would be
[string matching](//).
Using code such as
```lua
local code = "game.Players.SebbyTheGODKid:Destroy()"
local blocked = "game\.Players\.%w+\:Destroy()"
if blocked:match(code) then
  error("Player is locked")
end
loadstring(code)()
```
will work for most cases, but it won't stop
* variables
  ```lua
  players = game.Players
  players.SebbyTheGODKid:Destroy()
  ```
* string keys
  ```lua
  game["Players"]["SebbyTheGODKid"]:Destroy()
  ```
* using services
  ```lua
  game.Debris:AddItem(game.Players.SebbyTheGODKid, -1)
  ```
* calls to the LuaC api
  ```lua
  pcall(game.destroy, game.Players.SebbyTheGODKid)
  ````
So, how can we stop this?
## Function enviroments
**__Please note that `loadstring()` is deprecated, and will not work in LocalScripts, but will, however, work in a script with LoadStringEnabled__**

We can run code in a Sandbox to securely stop malicious attempts by using `setfenv`:
```lua
function sandbox(code)
  local env = getfenv(0)
  local newEnv = setmetatable({}, {
    __index = function(self, index)
      if index:lower() == "game" or index:lower() == "instance" or index:lower() == "workspace" then
        error("Can not acess Instance \"" .. index:lower() .. "\"")
      else
        return env[index]
      end
    end
  })
  local functionToRun = loadstring(code)
  setfenv(functionToRun, newEnv)
  functionToRun()
end
```
Now, we can execute our code by doing
```lua
sandbox([[
  if Instance then
    game.Players.SebbyTheGODKid:Destroy()
  else
    warn("I can't acess Instance!")
  end
]])
```
and it won't be able to do a thing. However, that is a problem.
This code is *too* sandboxed, we can only do `print` without it erroring.
### Building a better sandbox
We need to be sure that scripts can acess Instances without errors.
We need to ensure that
* `local y = obj.Property` -> `local y = sandbox(unsandbox(obj).Property)`
* `obj.Property = y` -> `unsandbox(obj).Property = unsandbox(y)`
Functions should also be taken care of
* `sandbox(f)` -> `function(...) return sandbox(f(unsandbox(...))) end`
* `unsandbox(f)` -> `function(...) return unsandbox(f(sandbox(...))) end`
by making a sandbox that still allows safe code, we will have a sucessfull script builder. \(like [mine](https://www.roblox.com/games/1393348839/Sebbys-Script-Builder)\)
```lua
local needssandboxing = function(o) return typeof(o) == "Instance" end 
sandbox = {}
 
-- A map of sandboxed items to their original counterparts.
-- The cache uses weak references so sandboxed objects can be collected if there are no references left to them anywhere else.
sandbox.cache = setmetatable({}, {__mode = "kv"})
 
-- Since below we used sandbox.any(safeDestroy) we don't need to get the original here
-- The passed argument 'obj' is already the unsandboxed instance
local function safeDestroy(obj)
    if obj:IsA("Player") then
        error("You cannot destroy a Player") -- simple error
    end obj:Destroy()
end
-- Let's try something more difficult: Hiding instances from GetChildren
-- For example: Let's hide everything which name starts with "Hidden"
-- If you have a model with those 4 instances: PartA, PartB, HiddenPart and PartC
-- Using GetChildren on the model would return a table with: PartA, PartB and PartC
local function safeGetChildren(obj)
    local res = {}
    for k,v in pairs(obj:GetChildren()) do
    if not v.Name:match("^Hidden") then -- "^Hidden" checks if it starts with "Hidden", then inverse it with 'not'
            table.insert(res,v) -- Name doesn't start with "Hidden", so let's add it to the results
        end
    end
    return res -- Since we use sandbox.any(safeGetChildren) below, this table will be automaticly sandboxed
end
 
sandbox.mt = {
    __index = function(self, k)
        local original = sandbox.cache[self]
 
        -- todo: add logic here to filter property/method reading
 
        local v = original[k]
 
        -- example: filtering destroy to not work on players
        if k:lower() == "destroy" then
            return sandbox.any(safeDestroy) -- easier for above
        elseif k:lower() == "getchildren" or k:lower() == "children" then
            return sandbox.any(safeGetChildren) -- easier for above
        end
 
        return sandbox.any(v)
    end,
    __newindex = function(self, k, v)
        local original = sandbox.cache[self]
 
        -- todo: add logic here to filter property writing
 
        original[k] = unsandbox.any(v)
    end
}
--sandbox any object
function sandbox.any(a)
    if sandbox.cache[a] then
        -- already sandboxed
        return a
    elseif type(a) == "function" then
        return sandbox.func(a)
    elseif type(a) == "table" then
        return sandbox.table(a)
    elseif needssandboxing(a) then
        return sandbox.object(a)
    else
        --doesn't need sandboxing
        return value
    end
end
--sandbox instances and events
function sandbox.object(o)
    local sandboxed = setmetatable({}, sandbox.mt)
    sandbox.cache[sandboxed] = o
    return sandboxed
end
--sandbox a function
function sandbox.func(f)
    local sandboxed = function(...)
        return sandbox(f(unsandbox(...)))
    end
    sandbox.cache[sandboxed] = f
    return sandboxed
end
--sandbox a table. TODO: prevent crash on recursive tables.
function sandbox.table(t)
    local sandboxed = {}
    for k, v in pairs(t) do
        --by sandboxing every key and every value
        sandboxed[sandbox.any(k)] = sandbox.any(v)
    end
    return sandboxed
end
unsandbox = {}
--unsandbox any objects
unsandbox.any = function(a)
    if sandbox.cache[a] then
        --if we have it cached, return it
        return sandbox.cache[a]
    elseif type(a) == "function" then
        return unsandbox.func(a)
    elseif type(a) == "table"
        return unsandbox.table(a)
    else
        return a
    end
end
--unsandbox a table. TODO: prevent crash on recursive tables.
unsandbox.table = function(t)
    local unsandboxed = {}
    for k, v in pairs(t) do
        --by unsandboxing every key and every value
        unsandboxed[unsandbox.any(k)] = unsandbox.any(v)
    end
    return unsandboxed
end
--unsandbox a function (sandboxed -> sandboxed), such as one passed to an event handler, making it (raw -> raw)
unsandbox.func = function(f)
    local raw = function(...)
        return unsandbox(f(sandbox(...)))
    end
    sandbox.cache[f] = raw 
    return raw
end
 
-- make sandbox and unsandbox function acting on tuples
local callable_mt = {
   __call = function(self, first, ...)
       if select('#', ...) == 0 then
           return self.any(first)
       else
           return self.any(first), self(...)
       end
   end
}
 
setmetatable(sandbox, callable_mt)
setmetatable(unsandbox, callable_mt)
```
# getfenv
Returns the current enviroment being used by the first argument. The first argument can be excluded, a stack level, or
a function.

Setting the first argument to `0` gets the global enviroment.

_Example_:
```lua
var1 = 1
var2 = 2
getfenv()["var3"] = 3 -- > Sets "var3" to 3 without callling it seperately
print(var1 + var2) -- > 3
print(var3) -- > 3
```
# setfenv
Sets the enviroment of the given function, the first argument can be a function or a number containing the stack level.
Returns the given function.

When the first argument is `0`, it sets the global enviroment.

_Example_:
```lua
local a = "GlobalEnviroment"
print(a) -- > GlobalEnviroment
setfenv(1, {a = a}) -- We just changed the enviroment
-- print will no longer work, because the enviroment changed.
print(a) -- > Attempt to call method "print", a nil value
-- Instead, we will have to write it as "a.print"
-- as such, "a" is now the global enviroment, and therefore is nil
a.print(a) -- > nil
-- but "a" still maintains it's value, as long as we call it as itself
a.print(a.a) -- > "GlobalEnviroment"
```
<br /><br />
<small>Adapted from the [wiki's version]()</small>
