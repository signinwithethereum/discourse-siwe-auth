#!/usr/bin/env ruby
# Integration test: verifies EIP-6492 universal validator against a real RPC.
#
# Usage:
#   ruby test/smart_wallet_integration_test.rb
#   RPC_URL=https://your-rpc-provider.com ruby test/smart_wallet_integration_test.rb
#
# The universal validator handles EOA, EIP-1271, and EIP-6492 signatures
# in a single eth_call. We test with a known EOA signature (random key whose
# address has no contract code on mainnet).

require 'net/http'
require 'json'

$LOAD_PATH.unshift(*Dir[File.join(__dir__, '..', 'gems/3.4.8/gems/keccak-*/lib')])
require 'digest/keccak'

RPC_URL = ENV.fetch('RPC_URL', 'https://ethereum-rpc.publicnode.com')

# EIP-6492 universal validator bytecode (read from source of truth)
EIP6492_VALIDATOR_BYTECODE = File.read(File.join(__dir__, '..', 'lib/omniauth/strategies/siwe.rb'))
  .match(/EIP6492_VALIDATOR_BYTECODE = "([0-9a-f]+)"/)[1]

# Test vector: random key with NO contract code on mainnet.
# Address 0x05616f5E0B9a600D4D51DE3D0D24C5D6dD638BE0
# Verified via viem: validator returns 0x01 (valid), verifyMessage returns true.
TEST_ADDRESS   = "05616f5e0b9a600d4d51de3d0d24c5d6dd638be0"
TEST_MESSAGE   = "test.example.com wants you to sign in with your Ethereum account:\n" \
                 "0x05616f5E0B9a600D4D51DE3D0D24C5D6dD638BE0\n" \
                 "\n" \
                 "Sign in with Ethereum\n" \
                 "\n" \
                 "URI: https://test.example.com\n" \
                 "Version: 1\n" \
                 "Chain ID: 1\n" \
                 "Nonce: test123\n" \
                 "Issued At: 2024-01-01T00:00:00Z"
TEST_SIGNATURE = "ea337e906e34f485e054c5999ae2c97a8d346474633798a5c88fcb3e6a3f3964" \
                 "44f685fc1a43a743c54d6037dd6f3c0b516d35229c24fe2a8d03c7783cbc2d2b1c"
# Hash verified against viem.hashMessage output
TEST_HASH      = "f9e0abaf53d39c5b7e8122276cb46f6cf5b100d32ba23bd095889568c79a4d95"

def keccak256(data)
  Digest::Keccak.new(256).digest(data)
end

def bin_to_hex(bin)
  bin.unpack1('H*')
end

def prefix_message(message)
  "\x19Ethereum Signed Message:\n#{message.bytesize}#{message}"
end

def eth_call(to, data)
  uri = URI(RPC_URL)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = uri.scheme == 'https'
  http.open_timeout = 15
  http.read_timeout = 15
  req = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path, 'Content-Type' => 'application/json')
  call_params = { data: data }
  call_params[:to] = to if to
  req.body = {
    jsonrpc: '2.0',
    method: 'eth_call',
    params: [call_params, 'latest'],
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

def encode_validator_call(address, message_hash, signature)
  address_param = address.downcase.rjust(64, '0')
  hash_param = message_hash.rjust(64, '0')
  bytes_offset = "0000000000000000000000000000000000000000000000000000000000000060"
  sig_length = (signature.length / 2).to_s(16).rjust(64, '0')
  sig_padded = signature.ljust(((signature.length + 63) / 64) * 64, '0')

  "0x#{EIP6492_VALIDATOR_BYTECODE}#{address_param}#{hash_param}#{bytes_offset}#{sig_length}#{sig_padded}"
end

def parse_result(hex)
  return false if hex.nil?
  hex.gsub(/\A0+/, '') == '1'
end

# ---------- Run integration tests ----------

puts "Smart Wallet Integration Test (EIP-6492 Universal Validator)"
puts "RPC: #{RPC_URL}"
puts "=" * 60

# Test 1: Verify EIP-191 hash matches expected
puts "\n1. Verifying EIP-191 hash computation..."
prefixed = prefix_message(TEST_MESSAGE)
computed_hash = bin_to_hex(keccak256(prefixed))
if computed_hash == TEST_HASH
  puts "   PASS: Hash matches viem test vector"
else
  puts "   FAIL: Expected #{TEST_HASH}"
  puts "         Got      #{computed_hash}"
  exit 1
end

# Test 2: Verify test address has no code (validator requires this for EOA path)
puts "\n2. Checking test address has no contract code..."
uri = URI(RPC_URL)
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = uri.scheme == 'https'
http.open_timeout = 15
http.read_timeout = 15
req = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path, 'Content-Type' => 'application/json')
req.body = {
  jsonrpc: '2.0',
  method: 'eth_getCode',
  params: ["0x#{TEST_ADDRESS}", 'latest'],
  id: 1
}.to_json
response = http.request(req)
code_result = JSON.parse(response.body)
has_code = code_result['result'] && code_result['result'] != '0x' && code_result['result'] != '0x0'
if has_code
  puts "   SKIP: Address has code on this network — validator will use EIP-1271 path"
  puts "   (This is expected if you're using a non-mainnet RPC)"
  puts "   Skipping validator tests that require code-free address."
  puts "\n" + "=" * 60
  puts "Skipped (address has code). Hash test passed."
  exit 0
end
puts "   PASS: No code at address — validator will use EOA ecrecover path"

# Test 3: Valid signature via universal validator
puts "\n3. Verifying valid EOA signature via universal validator..."
data = encode_validator_call(TEST_ADDRESS, TEST_HASH, TEST_SIGNATURE)
puts "   Call data size: #{(data.length - 2) / 2} bytes"
result = eth_call(nil, data)
if result.nil?
  puts "   FAIL: RPC returned nil (check RPC_URL or network)"
  exit 1
end
if parse_result(result)
  puts "   PASS: Universal validator returned valid (0x01)"
else
  puts "   FAIL: Universal validator returned invalid"
  puts "   Raw result: #{result}"
  exit 1
end

# Test 4: Wrong signer address should fail
puts "\n4. Verifying wrong signer is rejected..."
wrong_address = "0000000000000000000000000000000000000001"
data = encode_validator_call(wrong_address, TEST_HASH, TEST_SIGNATURE)
result = eth_call(nil, data)
if !parse_result(result)
  puts "   PASS: Correctly rejected wrong signer"
else
  puts "   FAIL: Incorrectly accepted wrong signer"
  exit 1
end

# Test 5: Corrupted signature should fail
puts "\n5. Verifying corrupted signature is rejected..."
bad_sig = "ff" + TEST_SIGNATURE[2..]
data = encode_validator_call(TEST_ADDRESS, TEST_HASH, bad_sig)
result = eth_call(nil, data)
if !parse_result(result)
  puts "   PASS: Correctly rejected corrupted signature"
else
  puts "   FAIL: Incorrectly accepted corrupted signature"
  exit 1
end

# Test 6: Wrong message hash should fail
puts "\n6. Verifying wrong message hash is rejected..."
wrong_hash = "aa" * 32
data = encode_validator_call(TEST_ADDRESS, wrong_hash, TEST_SIGNATURE)
result = eth_call(nil, data)
if !parse_result(result)
  puts "   PASS: Correctly rejected wrong hash"
else
  puts "   FAIL: Incorrectly accepted wrong hash"
  exit 1
end

puts "\n" + "=" * 60
puts "All checks passed!"
