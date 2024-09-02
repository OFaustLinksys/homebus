#!/usr/bin/env lua

require "homebus"
require "uloop"

--[[
  A demo of homebus publisher binding. Should be run before subscriber.lua
--]]


uloop.init()

local conn = homebus.connect()
if not conn then
	error("Failed to connect to homebus")
end

local homebus_objects = {
	test = {
		hello = {
			function(req, msg)
				conn:reply(req, {message="foo"});
				print("Call to function 'hello'")
				for k, v in pairs(msg) do
					print("key=" .. k .. " value=" .. tostring(v))
				end
			end, {id = homebus.INT32, msg = homebus.STRING }
		},
		hello1 = {
			function(req)
				conn:reply(req, {message="foo1"});
				conn:reply(req, {message="foo2"});
				print("Call to function 'hello1'")
			end, {id = homebus.INT32, msg = homebus.STRING }
		},
		__subscriber_cb = function( subs )
			print("total subs: ", subs )
		end
	}
}

conn:add( homebus_objects )
print("Objects added, starting loop")

-- start time
local timer
local counter = 0
function t()
	counter = counter + 1
	local params = {
		count = counter
	}
	conn:notify( homebus_objects.test.__homebusobj, "test.alarm", params )
	timer:set(10000)
end
timer = uloop.timer(t)
timer:set(1000)


uloop.run()
