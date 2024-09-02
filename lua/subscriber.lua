#!/usr/bin/env lua

--[[
  A demo of homebus subscriber binding. Should be run after publisher.lua
--]]

require "homebus"
require "uloop"

uloop.init()

local conn = homebus.connect()
if not conn then
	error("Failed to connect to homebus")
end

local sub = {
	notify = function( msg, name )
		print("name:", name)
		print("  count:", msg["count"])
	end,
}

conn:subscribe( "test", sub )

uloop.run()
