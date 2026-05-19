-- ============================================================
-- RULECAST — NSE TEST SUITE
--
-- EXPECTED RESULTS (update when adding rules):
--   Total rules  : 9
--   Valid        : 6
--   Invalid      : 2
--   Incomplete   : 1
--
-- Run with: python3 main.py test → choose nse → file
-- ============================================================


-- ============================================================
-- VALID RULES
-- Must pass validate(). identity.name must start with "Valid_"
-- ============================================================

-- Valid_http-title.nse
description = [[
Retrieves the page title from the default web page of a web server.
Useful for quick service identification. References CVE-2021-44228 in banner checks.
See https://nmap.org/nsedoc/scripts/http-title.html
]]
author = "Diman Todorov"
license = "Same as Nmap --see https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
  return port.protocol == "tcp"
    and port.state == "open"
    and (port.service == "http" or port.service == "https")
end

action = function(host, port)
  local title = "HTTP Title"
  return title
end

-- Valid_ssh-hostkey.nse
description = [[
Shows SSH host keys for a remote machine.
Reports algorithm and fingerprint of each host key.
]]
author = "Kris Katterjohn"
license = "Same as Nmap --see https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}
version = "1.2"

portrule = function(host, port)
  return port.number == 22 and port.state == "open"
end

action = function(host, port)
  return "host key info"
end


-- ============================================================
-- INVALID RULES
-- Must fail validate(). identity.name must start with "Invalid_"
-- ============================================================

-- Invalid_syntax-error.nse
description = [[Bad syntax: missing closing parenthesis in portrule.]]
author = "Test"
license = "MIT"
categories = {"default"}

portrule = function(host port
  return true
end

action = function(host, port)
  return "test"
end

-- Invalid_no-action.nse
description = [[
Missing the mandatory action() function.
]]
author = "Test Author"
license = "MIT"
categories = {"safe"}

portrule = function(host, port)
  return port.state == "open"
end


-- ============================================================
-- NASTY / EDGE-CASE RULES  (optional)
-- No pass/fail expectation — result is observed only.
-- identity.name must start with "Nasty_"
-- ============================================================

-- Nasty_no-rule-type.nse
description = [[
Valid Lua syntax but missing portrule/hostrule.
Should produce a warning but not an error.
]]
author = "Edge Tester"
license = "MIT"
categories = {"default"}

action = function(host, port)
  return "no rule type"
end


-- ============================================================
-- REAL-WORLD RULES  (source: https://github.com/D4-project/Plum-Rules-NSE)
-- Must pass validate(). identity.name must start with "Valid_"
-- ============================================================

-- Valid_banner.nse
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
This is a robust banner scanner.
Connects to a TCP service, waits for a passive banner, sends two Enter
keystrokes if no data is received, and retries with "GET /" if the service
closes the connection or remains silent. The received banner is stored in
host.registry and reported in the script output in all cases.
]]

author = "CIRCL/Paul JUNG (Thanat0s)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe" }

---
-- @args smart-banner.wait Passive banner wait time in milliseconds.
--       Defaults to 500.
-- @args smart-banner.timeout Read timeout after sending data, in
--       milliseconds. Defaults to 2000.
-- @args smart-banner.maxbytes Maximum banner bytes to collect.
--       Defaults to 4096.
--
-- @usage
-- nmap -sV --script ./smart-banner.nse -p <ports> <target>
--
-- @output
-- |_ smart-banner: SSH-2.0-OpenSSH_9.2p1\x0A

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

local SCRIPT_KEY = SCRIPT_NAME

local function get_arg(name, default)
  return tonumber(stdnse.get_script_args(SCRIPT_KEY .. "." .. name)) or default
end

local function is_close_error(err)
  if not err then
    return false
  end

  err = string.lower(tostring(err))
  return err:match("closed") or err:match("eof") or err:match("reset")
end

local function replace_nonprint(data, len)
  local output = {}
  local count = 0

  for char in data:gmatch(".") do
    local byte = char:byte()
    if byte < 32 or byte > 126 then
      output[#output + 1] = string.format("\\x%02X", byte)
      count = count + 4
    else
      output[#output + 1] = char
      count = count + 1
    end

    if type(len) == "number" and count >= len then
      break
    end
  end

  return table.concat(output)
end

local function save_banner(host, port, result)
  host.registry[SCRIPT_KEY] = host.registry[SCRIPT_KEY] or {}
  host.registry[SCRIPT_KEY][port.number .. "/" .. port.protocol] = result
end

local function extra_output()
  return (nmap.verbosity() - nmap.debugging() > 0 and nmap.verbosity() - nmap.debugging()) or 0
end

local function output_banner(out)
  if type(out) ~= "string" or out == "" then
    return nil
  end

  local filename = SCRIPT_NAME
  local line_len = 75
  local fline_offset = 5
  local fline_len

  if filename:len() < (line_len - fline_offset) then
    fline_len = line_len - 1 - filename:len() - fline_offset
  else
    fline_len = 0
  end

  local sline_len = line_len - 1 - (fline_offset - 2)
  local total_out_chars

  if fline_len > 0 then
    total_out_chars = fline_len + (extra_output() * sline_len)
  else
    total_out_chars = (1 + extra_output()) * sline_len
  end

  out = replace_nonprint(out:match("^%s*(.-)%s*$"), 1 + total_out_chars)

  if out:len() > total_out_chars then
    while out:len() > total_out_chars do
      if out:sub(-4, -1):match("\\x%x%x") then
        out = out:sub(1, -5)
      else
        out = out:sub(1, -2)
      end
    end
    out = ("%s..."):format(out:sub(1, total_out_chars - 3))
  end

  local ptr = fline_len
  local lines = {}
  while true do
    if out:len() >= ptr then
      lines[#lines + 1] = (ptr > 0 and out:sub(1, ptr)) or " "
      out = out:sub(ptr + 1)
      ptr = sline_len
    else
      lines[#lines + 1] = out
      break
    end
  end

  return table.concat(lines, "\n")
end

local function connect_socket(host, port, timeout)
  local socket = nmap.new_socket()
  socket:set_timeout(timeout)

  local status, err = socket:connect(host.ip, port.number, port.protocol)
  if not status then
    socket:close()
    return nil, err
  end

  return socket
end

local function read_available(socket, first_timeout, next_timeout, max_bytes)
  local chunks = {}
  local total = 0
  local last_error

  socket:set_timeout(first_timeout)

  while total < max_bytes do
    local status, data = socket:receive_bytes(1)
    if not status then
      last_error = data
      break
    end

    if not data or data == "" then
      break
    end

    if total + #data > max_bytes then
      data = data:sub(1, max_bytes - total)
    end

    table.insert(chunks, data)
    total = total + #data
    socket:set_timeout(next_timeout)
  end

  if #chunks > 0 then
    return table.concat(chunks), nil
  end

  return "", last_error
end

local function attempt_passive_then_enter(host, port, wait_timeout, read_timeout, max_bytes)
  local socket, err = connect_socket(host, port, read_timeout)
  if not socket then
    return {
      stage = "connect",
      banner = "",
      closed = false,
      error = "connect failed: " .. (err or "unknown error")
    }
  end

  local banner, read_error = read_available(socket, wait_timeout, 250, max_bytes)
  if banner ~= "" then
    socket:close()
    return {
      stage = "passive",
      banner = banner,
      closed = false
    }
  end

  if is_close_error(read_error) then
    socket:close()
    return {
      stage = "passive",
      banner = "",
      closed = true,
      error = read_error
    }
  end

  local status, send_error = socket:send("\r\n\r\n")
  if not status then
    socket:close()
    return {
      stage = "enter",
      banner = "",
      closed = is_close_error(send_error),
      error = send_error
    }
  end

  banner, read_error = read_available(socket, read_timeout, 250, max_bytes)
  socket:close()

  return {
    stage = "enter",
    banner = banner,
    closed = is_close_error(read_error),
    error = read_error
  }
end

local function attempt_get(host, port, read_timeout, max_bytes)
  local socket, err = connect_socket(host, port, read_timeout)
  if not socket then
    return {
      stage = "get",
      banner = "",
      closed = false,
      error = "reconnect failed: " .. (err or "unknown error")
    }
  end

  local status, send_error = socket:send("GET /\r\n\r\n")
  if not status then
    socket:close()
    return {
      stage = "get",
      banner = "",
      closed = is_close_error(send_error),
      error = send_error
    }
  end

  local banner, read_error = read_available(socket, read_timeout, 250, max_bytes)
  socket:close()

  return {
    stage = "get",
    banner = banner,
    closed = is_close_error(read_error),
    error = read_error
  }
end

action = function(host, port)
  local wait_timeout = get_arg("wait", 500)
  local read_timeout = get_arg("timeout", 2000)
  local max_bytes = get_arg("maxbytes", 4096)

  local result = attempt_passive_then_enter(host, port, wait_timeout, read_timeout, max_bytes)
  if result.closed or result.banner == "" then
    result = attempt_get(host, port, read_timeout, max_bytes)
  end

  save_banner(host, port, result)
  return output_banner(result.banner)
end

-- Valid_http-mm-sha-favicon.nse
local http = require "http"
local nmap = require "nmap"
local openssl = require "openssl"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"
local base64 = require "base64"

description = [[
Gets the favicon from a web page then hash it using md5, sha256 and the method
"http.favicon.hash" used by shodan.io murmur3_32(base64(favicon))
The results is displayed as a signed integer.

If the script argument <code>favicon.uri</code> is given, that relative URI is
always used to find the favicon. Otherwise, first the page at the root of the
web server is retrieved and parsed for a <code><link rel="icon"></code>
element. If that fails, the icon is looked for in <code>/favicon.ico</code>. If
a <code><link></code> favicon points to a different host or port, it is ignored.
]]
author = "CIRCL/Paul JUNG (Thanat0s)"
license = "GNU Affero General Public Licence https://www.gnu.org/licenses/agpl-3.0.en.html"

---
-- @args favicon.uri URI that will be requested for favicon.
-- @args favicon.root Web server path to search for favicon.
--
-- @usage
-- nmap --script=http-favicon.nse \
--    --script-args favicon.root=<root>,favicon.uri=<uri>
-- @output
-- |_ http-mmfavicon: signed integer

-- HTTP default favicon murmur32 (shodan like) / md5 / sha256 hash
-- rev 1.0 (2025-10-10)
-- Original NASL script inspiration by Javier Fernandez-Sanguino Pena
-- NSE http-favicon.nse by Vlatko Kosturjak
-- SHA256 Implementation by OGabrieLima https://github.com/OGabrieLima (2024-04-08)

categories = {"default", "discovery", "safe"}
portrule = shortport.http

--[[
For thoses who wonder, in NMAP v7.94, LUA NSE is bundled with the following Openssl module:
 -      bignum_dec2bn
 -      bignum_pseudo_rand
 -      supported_ciphers
 -      supported_digests
 -      ripemd160
 -      DES_string_to_key
 -      bignum_num_bytes
 -      bignum_bn2hex
 -      decrypt
 -      bignum_bn2mpi
 -      bignum_mod_exp
 -      bignum_set_bit
 -      bignum_rand
 -      encrypt
 -      hmac
 -      digest
 -      bignum_div
 -      bignum_bn2dec
 -      bignum_bin2bn
 -      bignum_clear_bit
 -      md5
 -      bignum_bn2bin
 -      bignum_num_bits
 -      md4
 -      rand_pseudo_bytes
 -      bignum_is_safe_prime
 -      bignum_add
 -      rand_bytes
 -      bignum_hex2bn
 -      sha1
 -      bignum_is_bit_set
 -      bignum_is_prime
]]--

-- Auxiliary function: right rotation (bitwise)
local function bit_ror(x, y)
  return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF
end

-- helpers since lib int seems not available in nmap
local function toUint32(x) return x % 0x100000000 end
local function toInt32(x)
    x = x % 0x100000000
    if x >= 0x80000000 then x = x - 0x100000000 end
    return x
end
local function rshift(x,n) return math.floor(toUint32(x) / 2^n) end
local function lshift(x,n) return toUint32(toUint32(x) * 2^n) end
local function rol(x,n) return toUint32(lshift(x,n) + rshift(x,32-n)) end
local function bxor(a,b)
    local r, bitval = 0,1
    for i=1,32 do
        if (a % 2 + b % 2) % 2 == 1 then r = r + bitval end
        a = math.floor(a/2); b = math.floor(b/2); bitval = bitval * 2
    end
    return toUint32(r)
end
local function imul32(a,b)
    local a_lo, a_hi = a % 0x10000, math.floor(a / 0x10000)
    local b_lo, b_hi = b % 0x10000, math.floor(b / 0x10000)
    local low = a_lo * b_lo
    local mid = a_lo * b_hi + a_hi * b_lo
    return toUint32(low + mid * 0x10000)
end

-- Main function: MurmurHash3 32-bits
local function murmur3_32(data, seed)
    local h1 = seed or 0
    local c1, c2 = 0xcc9e2d51, 0x1b873593
    local len = #data
    local nblocks = math.floor(len/4)

    -- body
    for i=0,nblocks-1 do
        local j = i*4 + 1
        local k1 = data:byte(j) + lshift(data:byte(j+1),8) + lshift(data:byte(j+2),16) + lshift(data:byte(j+3),24)
        k1 = imul32(k1, c1)
        k1 = rol(k1,15)
        k1 = imul32(k1, c2)
        h1 = bxor(h1, k1)
        h1 = rol(h1,13)
        h1 = toUint32(imul32(h1,5) + 0xe6546b64)
    end

    -- tail
    local tail_index = nblocks*4 + 1
    local k1 = 0
    local rem = len % 4
    if rem == 3 then k1 = lshift(data:byte(tail_index+2),16) end
    if rem >= 2 then k1 = bxor(k1, lshift(data:byte(tail_index+1),8)) end
    if rem >= 1 then
        k1 = bxor(k1, data:byte(tail_index))
        k1 = imul32(k1, c1)
        k1 = rol(k1,15)
        k1 = imul32(k1, c2)
        h1 = bxor(h1,k1)
    end

    -- finalization
    h1 = bxor(h1, len)
    h1 = bxor(h1, rshift(h1,16))
    h1 = imul32(h1,0x85ebca6b)
    h1 = bxor(h1,rshift(h1,13))
    h1 = imul32(h1,0xc2b2ae35)
    h1 = bxor(h1,rshift(h1,16))

    return toInt32(h1)
end

-- Main function: SHA256
sha256 = function(message)
  local k = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  }

  local function preprocess(message)
      local len = #message
      local bitLen = len * 8
      message = message .. "\128" -- append single '1' bit

      local zeroPad = 64 - ((len + 9) % 64)
      if zeroPad ~= 64 then
          message = message .. string.rep("\0", zeroPad)
      end

      -- append length
      message = message .. string.char(
          bitLen >> 56 & 0xFF,
          bitLen >> 48 & 0xFF,
          bitLen >> 40 & 0xFF,
          bitLen >> 32 & 0xFF,
          bitLen >> 24 & 0xFF,
          bitLen >> 16 & 0xFF,
          bitLen >> 8 & 0xFF,
          bitLen & 0xFF
      )

      return message
  end

  local function chunkify(message)
      local chunks = {}
      for i = 1, #message, 64 do
          table.insert(chunks, message:sub(i, i + 63))
      end
      return chunks
  end

  local function processChunk(chunk, hash)
      local w = {}

      for i = 1, 64 do
          if i <= 16 then
              w[i] = string.byte(chunk, (i - 1) * 4 + 1) << 24 |
                     string.byte(chunk, (i - 1) * 4 + 2) << 16 |
                     string.byte(chunk, (i - 1) * 4 + 3) << 8 |
                     string.byte(chunk, (i - 1) * 4 + 4)
          else
              local s0 = bit_ror(w[i - 15], 7) ~ bit_ror(w[i - 15], 18) ~ (w[i - 15] >> 3)
              local s1 = bit_ror(w[i - 2], 17) ~ bit_ror(w[i - 2], 19) ~ (w[i - 2] >> 10)
              w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
          end
      end

      local a, b, c, d, e, f, g, h = table.unpack(hash)

      for i = 1, 64 do
          local s1 = bit_ror(e, 6) ~ bit_ror(e, 11) ~ bit_ror(e, 25)
          local ch = (e & f) ~ ((~e) & g)
          local temp1 = (h + s1 + ch + k[i] + w[i]) & 0xFFFFFFFF
          local s0 = bit_ror(a, 2) ~ bit_ror(a, 13) ~ bit_ror(a, 22)
          local maj = (a & b) ~ (a & c) ~ (b & c)
          local temp2 = (s0 + maj) & 0xFFFFFFFF

          h = g
          g = f
          f = e
          e = (d + temp1) & 0xFFFFFFFF
          d = c
          c = b
          b = a
          a = (temp1 + temp2) & 0xFFFFFFFF
      end

      return (hash[1] + a) & 0xFFFFFFFF,
             (hash[2] + b) & 0xFFFFFFFF,
             (hash[3] + c) & 0xFFFFFFFF,
             (hash[4] + d) & 0xFFFFFFFF,
             (hash[5] + e) & 0xFFFFFFFF,
             (hash[6] + f) & 0xFFFFFFFF,
             (hash[7] + g) & 0xFFFFFFFF,
             (hash[8] + h) & 0xFFFFFFFF
  end

  message = preprocess(message)
  local chunks = chunkify(message)

  local hash = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
  for _, chunk in ipairs(chunks) do
      hash = {processChunk(chunk, hash)}
  end

  local result = ""
  for _, h in ipairs(hash) do
      result = result .. string.format("%08x", h)
  end

  return result
end

local function add_crlf(str, width)
    width = width or 76
    local t = {}
    for i = 1, #str, width do
        table.insert(t, str:sub(i, i + width - 1))
    end
    local s = table.concat(t, "\n")
    return s .. "\n"
end

action = function(host, port)
  local md5sum,answer
  local match
  local status, favicondb
  local results = stdnse.output_table()
   -- local results = {}
  local index, icon
  local favicon_file
  local root = ""

  if(stdnse.get_script_args('favicon.root')) then
    root = stdnse.get_script_args('favicon.root')
  end

  -- If parameter favicon.uri is given, we fetch it, always and only this.
  local favicon_uri = stdnse.get_script_args("favicon.uri")
  if(favicon_uri) then
    favicon_file = root .. "/" .. favicon_uri
    answer = http.get( host, port, favicon_file)
    stdnse.debug4("Using URI %s", favicon_uri)
  else
    -- Otherwise, first try parsing the home page "/" for favicon reference.
    index = http.get( host, port, root .. "/" )
    if index.status == 200 or index.status == 503 then
      -- find the favicon pattern
      icon = parseIcon( index.body )
      -- if we find a pattern, we fetch it.
      if icon then
        local hostname = host.targetname or (host.name ~= "" and host.name) or host.ip
        stdnse.debug1("Got icon URL %s.", icon)
        local icon_host, icon_port, icon_path = parse_url_relative(icon, hostname, port.number, root)
        if (icon_host == host.ip or
          icon_host == host.targetname or
          icon_host == (host.name ~= '' and host.name)) and
          icon_port == port.number then
          -- request the favicon
          answer = http.get( icon_host, icon_port, icon_path )
          favicon_file = icon_path
        else
          answer = nil
        end
      else
        answer = nil
      end
    end

    -- If that didn't work, try /favicon.ico.
    if not answer or answer.status ~= 200 then
      favicon_file = root .. "/favicon.ico"
      answer = http.get( host, port, favicon_file )
      stdnse.debug4("Using default URI.")
    end
  end

-- Finaly if we have a favicon, we hash it.
if answer and answer.status == 200 then
    stdnse.debug1("Favicon found.")
    local debugs = ""
    -- MurmurHash3 32 bits should be done on a B64 CLRF enabled dump.
    local rb64 = add_crlf(base64.enc(answer.body)) 
    results.favicon_file = favicon_file
    results.favicon_mmhash = murmur3_32(rb64)
    md5sum = stdnse.tohex(openssl.md5(answer.body))
    results.favicon_md5 = md5sum
    local sha256sum=sha256(answer.body)
    results.favicon_sha256 = sha256sum
    
    if nmap.verbosity() > 1  then
        local hex_debug = {}
        for i = 1, 128 do  
            hex_debug[#hex_debug+1] = string.format("%02X", rb64:byte(i))
        end
        -- In debug mode, shows the first bytes of favicon file.
        local hex_string = table.concat(hex_debug, "")
        results.debug = sha256sum .. " " .. "->" .. hex_string .. "<-"
    end
else
    stdnse.debug1("No favicon found.")
    return
end
return results
end

local function dirname(path)
  local dir
  dir = string.match(path, "^(.*)/")
  return dir or ""
end

-- Return a URL's host, port, and path, filling in the results with the given
-- host, port, and path if the URL is relative. Return nil if the scheme is not
-- "http" or "https".
function parse_url_relative(u, host, port, path)
  local scheme, abspath
  u = url.parse(u)
  scheme = u.scheme or "http"
  if not (scheme == "http" or scheme == "https") then
    return nil
  end
  abspath = u.path or ""
  if not string.find(abspath, "^/") then
    abspath = dirname(path) .. "/" .. abspath
  end
  return u.host or host, u.port or url.get_default_port(scheme), abspath
end

function parseIcon( body )
  local _, i, j
  local rel, href, word

  -- Loop through link elements.
  i = 0
  while i do
    _, i = string.find(body, "<%s*[Ll][Ii][Nn][Kk]%s", i + 1)
    if not i then
      return nil
    end
    -- Loop through attributes.
    j = i
    while true do
      local name, quote, value
      _, j, name, quote, value = string.find(body, "^%s*(%w+)%s*=%s*([\"'])(.-)%2", j + 1)
      if not j then
        break
      end
      if string.lower(name) == "rel" then
        rel = value
      elseif string.lower(name) == "href" then
        href = value
      end
    end
    for word in string.gmatch(rel or "", "%S+") do
      if string.lower(word) == "icon" then
        return href
      end
    end
  end
end

-- Valid_ivanti_epmm.nse
description = [[
Detect Ivanti EPMM Hosts

Apply with host having the PLUM match :
"http_server:server"

This NSE Checks for Ivanti EPMM MDM by requesting a known API endpoint.
Detection requires:
- HTTP 401 on known API endpoint
- Presence of Server header with value "server"
- Random page returning 404 (not 401)
- Register page /mifs/c/i/reg/reg.html
https://help.ivanti.com/mi/help/en_us/CORE/12.x/api2/APIv2/IvantiEPMM_V2APIGuide.pdf
]]
author = "CIRCL/Paul JUNG (Thanat0s)"
license = "GNU Affero General Public Licence https://www.gnu.org/licenses/agpl-3.0.en.html"

categories = {"discovery", "safe"}

local http = require "http"
local shortport = require "shortport"

portrule = shortport.ssl

-- Generate a random string using only A–Z characters
local function generate_random_uppercase(length)
    local charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local result = {}

    for index = 1, length do
        local random_index = math.random(1, #charset)
        result[index] = charset:sub(random_index, random_index)
    end

    return table.concat(result)
end

-- Example usage
local random_string = generate_random_uppercase(12)


action = function(host, port)
    local api_path = "/api/v2/appinventory/apps"

    local random_string = generate_random_uppercase(12)
    local random_path = "/" .. random_string

    -- First request: known Ivanti API endpoint
    local api_response = http.get(host, port, api_path, {
        ssl = true,
        timeout = 5000
    })

    if not api_response or api_response.status ~= 401 then
        return "Not Detected"
    end

    -- Verify Server header value
    local server_header = api_response.header["server"]
    if not server_header or server_header ~= "server" then
        return "Not Detected"
    end

    -- Second request: random page must return 404 (not 401)
    local random_response = http.get(host, port, random_path, {
        ssl = true,
        timeout = 5000
    })

    if not random_response or random_response.status ~= 404 then
        return "Not Detected"
    end

    return "PLUMTAG:Ivanti_EPPM"
end


-- Valid_modbus.nse
local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"

description = [[
Quick Modbus/TCP identification.
Sends a Read Device Identification request and extracts printable strings.
]]

author = "Plum"
license = "Same as Nmap"
categories = {"discovery", "safe"}

-- portrule = shortport.port_or_service(502, "modbus", "tcp")
portrule = function(host, port)
  return port.protocol == "tcp" and port.number == 502
end
-- Read a 16-bit big endian integer from a string
local function read_uint16_be(data, index)
  local high_byte = data:byte(index) or 0
  local low_byte = data:byte(index + 1) or 0
  return high_byte * 256 + low_byte
end

-- Extract printable chunks from binary data
local function extract_printable_chunks(data)
  local chunks = {}

  -- Replace non-printable bytes with spaces
  data = data:gsub("[^\32-\126]", " ")

  -- Collect meaningful chunks
  for value in data:gmatch("%S[%S ]*") do
    value = value:gsub("^%s+", ""):gsub("%s+$", "")
    if #value >= 3 then
      table.insert(chunks, value)
    end
  end

  return table.concat(chunks, " ")
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local connect_status, connect_error = socket:connect(host, port)
  if not connect_status then
    return "connection failed: " .. (connect_error or "unknown error")
  end

  local request = string.char(
    0x00, 0x01, -- Transaction ID
    0x00, 0x00, -- Protocol ID
    0x00, 0x05, -- Length
    0x00,       -- Unit ID
    0x2B,       -- Function
    0x0E,       -- MEI Type
    0x01,       -- Read Device ID code
    0x00        -- Object ID
  )

  local send_status, send_error = socket:send(request)
  if not send_status then
    socket:close()
    return "send failed: " .. (send_error or "unknown error")
  end

  -- Important: receive_bytes(7) may return MORE than 7 bytes
  local receive_status, response = socket:receive_bytes(7)
  if not receive_status or not response or #response < 7 then
    socket:close()
    return "no valid response"
  end

  local header = response:sub(1, 7)
  local body = response:sub(8)

  -- MBAP length includes Unit ID, so body size is length - 1
  local expected_body_length = read_uint16_be(header, 5) - 1
  if expected_body_length <= 0 then
    socket:close()
    return "invalid response length"
  end

  -- If first read already included full body, do not read again
  local missing_bytes = expected_body_length - #body
  if missing_bytes > 0 then
    local body_status, more_body = socket:receive_bytes(missing_bytes)
    socket:close()

    if not body_status or not more_body then
      return "failed to read response body"
    end

    body = body .. more_body
  else
    socket:close()
    body = body:sub(1, expected_body_length)
  end

  local identification = extract_printable_chunks(body)
  if identification == "" then
    return "no printable modbus identification found"
  end

  return identification
end
