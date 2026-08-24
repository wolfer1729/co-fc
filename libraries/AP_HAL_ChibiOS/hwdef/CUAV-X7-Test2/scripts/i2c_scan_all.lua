-- Scans every I2C bus (per I2C_ORDER: 0=I2C3, 1=I2C1, 2=I2C2, 3=I2C4/BMM350)
-- and reports any address that ACKs, over GCS STATUSTEXT.

---@diagnostic disable: need-check-nil

local BUS_NAMES = {"I2C3", "I2C1", "I2C2", "I2C4"}
local NUM_BUSES = 4

local bus_idx = 0
local address = 1
local found_this_bus = 0
local dev = nil

local function start_bus(idx)
  dev = i2c:get_device(idx, 0)
  dev:set_retries(3)
  address = 1
  found_this_bus = 0
  gcs:send_text(0, "I2C scan: bus " .. BUS_NAMES[idx + 1] .. " (idx " .. tostring(idx) .. ")")
end

start_bus(bus_idx)

function update()
  dev:set_address(address)
  if dev:read_registers(0) then
    gcs:send_text(0, "  ACK 0x" .. string.format("%02X", address) .. " on " .. BUS_NAMES[bus_idx + 1])
    found_this_bus = found_this_bus + 1
  end

  address = address + 1
  if address >= 0x78 then
    gcs:send_text(0, "I2C scan: bus " .. BUS_NAMES[bus_idx + 1] .. " done, " .. tostring(found_this_bus) .. " found")
    bus_idx = bus_idx + 1
    if bus_idx >= NUM_BUSES then
      gcs:send_text(0, "I2C scan: ALL BUSES COMPLETE")
      bus_idx = 0
      start_bus(bus_idx)
      return update, 30000 -- pause 30s then repeat the whole sweep
    end
    start_bus(bus_idx)
  end

  return update, 60
end

return update()
