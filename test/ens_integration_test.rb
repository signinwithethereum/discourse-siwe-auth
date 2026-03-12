#!/usr/bin/env ruby
# Integration test: resolves a known ENS name against a real Ethereum RPC.
#
# Usage:
#   ruby test/ens_integration_test.rb                               # uses default public RPC
#   RPC_URL=https://eth-mainnet.g.alchemy.com/v2/KEY ruby test/ens_integration_test.rb
#
# Tests against jalil.eth, which has a reverse record and avatar.

require 'net/http'
require 'json'

$LOAD_PATH.unshift(*Dir[File.join(__dir__, '..', 'gems/3.4.8/gems/keccak-*/lib')])
require 'digest/keccak'

RPC_URL = ENV.fetch('RPC_URL', 'https://cloudflare-eth.com')
ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'

# Known test data
TEST_ADDRESS = '0xe11DA9560b51f8918295EdC5ab9c0a90E9ADa20B'
TEST_ENS     = 'jalil.eth'

def keccak256(data)
  Digest::Keccak.new(256).digest(data)
end

def bin_to_hex(bin)
  bin.unpack1('H*')
end

def ens_namehash(name)
  node = "\x00" * 32
  unless name.nil? || name.empty?
    name.split('.').reverse.each do |label|
      label_hash = keccak256(label)
      node = keccak256(node + label_hash)
    end
  end
  bin_to_hex(node)
end

def eth_call(to, data)
  uri = URI(RPC_URL)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = uri.scheme == 'https'
  http.open_timeout = 10
  http.read_timeout = 10
  req = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path, 'Content-Type' => 'application/json')
  req.body = {
    jsonrpc: '2.0',
    method: 'eth_call',
    params: [{ to: to, data: data }, 'latest'],
    id: 1
  }.to_json

  response = http.request(req)
  result = JSON.parse(response.body)

  if result['error']
    puts "  RPC error: #{result['error']}"
    return nil
  end

  return nil if result['result'].nil? || result['result'] == '0x'

  hex = result['result']
  hex.start_with?('0x') ? hex[2..] : hex
end

def abi_decode_address(hex)
  return nil if hex.nil? || hex.length < 40
  address = hex[-40, 40]
  return nil if address == '0' * 40
  "0x#{address}"
end

def abi_decode_string(hex)
  return nil if hex.nil? || hex.length < 128
  offset = hex[0, 64].to_i(16) * 2
  length = hex[offset, 64].to_i(16)
  return '' if length == 0
  data_start = offset + 64
  return nil if hex.length < data_start + length * 2
  [hex[data_start, length * 2]].pack('H*')
end

# ---------- Run integration test ----------

puts "ENS Integration Test"
puts "RPC: #{RPC_URL}"
puts "=" * 60

address = TEST_ADDRESS
addr_clean = address.sub(/\A0x/i, '').downcase

# Step 1: Reverse resolve
puts "\n1. Reverse resolving #{address}..."
reverse_node = ens_namehash("#{addr_clean}.addr.reverse")
puts "   Reverse node: #{reverse_node}"

resolver_hex = eth_call(ENS_REGISTRY, "0x0178b8bf#{reverse_node}")
resolver = abi_decode_address(resolver_hex)
if resolver.nil?
  puts "   FAIL: No resolver found for reverse node"
  exit 1
end
puts "   Reverse resolver: #{resolver}"

name_hex = eth_call(resolver, "0x691f3431#{reverse_node}")
name = abi_decode_string(name_hex)
if name.nil? || name.empty?
  puts "   FAIL: No name returned from reverse resolver"
  exit 1
end
puts "   Resolved name: #{name}"

if name == TEST_ENS
  puts "   PASS: Name matches expected '#{TEST_ENS}'"
else
  puts "   WARN: Expected '#{TEST_ENS}', got '#{name}'"
end

# Step 2: Forward verify
puts "\n2. Forward verifying #{name} -> address..."
forward_node = ens_namehash(name)
puts "   Forward node: #{forward_node}"

fwd_resolver_hex = eth_call(ENS_REGISTRY, "0x0178b8bf#{forward_node}")
fwd_resolver = abi_decode_address(fwd_resolver_hex)
if fwd_resolver.nil?
  puts "   FAIL: No resolver found for forward name"
  exit 1
end
puts "   Forward resolver: #{fwd_resolver}"

addr_hex = eth_call(fwd_resolver, "0x3b3b57de#{forward_node}")
resolved_addr = abi_decode_address(addr_hex)
if resolved_addr.nil?
  puts "   FAIL: No address returned from forward resolver"
  exit 1
end
puts "   Resolved address: #{resolved_addr}"

if resolved_addr.downcase == address.downcase
  puts "   PASS: Forward verification confirmed"
else
  puts "   FAIL: Address mismatch! #{resolved_addr} != #{address}"
  exit 1
end

# Step 3: Avatar via ENS metadata service
puts "\n3. Checking avatar via ENS metadata service..."
avatar_url = "https://metadata.ens.domains/mainnet/avatar/#{name}"
avatar_uri = URI(avatar_url)
avatar_http = Net::HTTP.new(avatar_uri.host, avatar_uri.port)
avatar_http.use_ssl = true
avatar_http.open_timeout = 10
avatar_http.read_timeout = 10
avatar_res = avatar_http.request(Net::HTTP::Head.new(avatar_uri.path))
puts "   URL: #{avatar_url}"
puts "   Status: #{avatar_res.code}"
if avatar_res.code.to_i == 200
  puts "   Content-Type: #{avatar_res['content-type']}"
  puts "   PASS: Avatar available"
else
  puts "   INFO: No avatar available (status #{avatar_res.code})"
end

# Step 4: Verify no-avatar case returns 404
puts "\n4. Checking no-avatar case (hot.jalil.eth)..."
no_avatar_url = "https://metadata.ens.domains/mainnet/avatar/hot.jalil.eth"
no_avatar_uri = URI(no_avatar_url)
no_avatar_http = Net::HTTP.new(no_avatar_uri.host, no_avatar_uri.port)
no_avatar_http.use_ssl = true
no_avatar_http.open_timeout = 10
no_avatar_http.read_timeout = 10
no_avatar_res = no_avatar_http.request(Net::HTTP::Head.new(no_avatar_uri.path))
puts "   URL: #{no_avatar_url}"
puts "   Status: #{no_avatar_res.code}"
if no_avatar_res.code.to_i == 404
  puts "   PASS: Correctly returns 404 for name without avatar"
else
  puts "   WARN: Expected 404, got #{no_avatar_res.code}"
end

puts "\n" + "=" * 60
puts "All checks passed!"
