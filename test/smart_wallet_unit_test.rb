#!/usr/bin/env ruby
# Unit tests for EIP-6492 universal validator ABI encoding and result parsing.
# No RPC or native crypto dependencies needed.
#
# Run: ruby test/smart_wallet_unit_test.rb

$LOAD_PATH.unshift(*Dir[File.join(__dir__, '..', 'gems/3.4.8/gems/keccak-*/lib')])
require 'digest/keccak'
require 'minitest/autorun'

# Standalone reimplementations of the helpers under test.
module SmartWalletHelpers
  module_function

  def keccak256(data)
    Digest::Keccak.new(256).digest(data)
  end

  def bin_to_hex(bin)
    bin.unpack1('H*')
  end

  # Mirrors Eth::Signature.prefix_message
  def prefix_message(message)
    "\x19Ethereum Signed Message:\n#{message.bytesize}#{message}"
  end

  # Mirrors smart_wallet_valid? ABI encoding logic
  def encode_validator_args(address_hex, message_hash_hex, signature_hex)
    address_param = address_hex.downcase.rjust(64, '0')
    hash_param = message_hash_hex.rjust(64, '0')
    sig_bytes = signature_hex
    bytes_offset = "0000000000000000000000000000000000000000000000000000000000000060"
    sig_length = (sig_bytes.length / 2).to_s(16).rjust(64, '0')
    sig_padded = sig_bytes.ljust(((sig_bytes.length + 63) / 64) * 64, '0')

    "#{address_param}#{hash_param}#{bytes_offset}#{sig_length}#{sig_padded}"
  end

  # Mirrors the result parsing in smart_wallet_valid?
  def parse_validator_result(hex_without_0x)
    return false if hex_without_0x.nil?
    hex_without_0x.gsub(/\A0+/, '') == '1'
  end
end

class EIP191HashTest < Minitest::Test
  # Verify that the EIP-191 hashing matches the viem test vector.
  # Message: SIWE message signed by a random key (address with no code on mainnet).
  SIWE_MESSAGE = "test.example.com wants you to sign in with your Ethereum account:\n" \
                 "0x05616f5E0B9a600D4D51DE3D0D24C5D6dD638BE0\n" \
                 "\n" \
                 "Sign in with Ethereum\n" \
                 "\n" \
                 "URI: https://test.example.com\n" \
                 "Version: 1\n" \
                 "Chain ID: 1\n" \
                 "Nonce: test123\n" \
                 "Issued At: 2024-01-01T00:00:00Z"

  # Expected hash produced by viem.hashMessage(SIWE_MESSAGE)
  EXPECTED_HASH = "f9e0abaf53d39c5b7e8122276cb46f6cf5b100d32ba23bd095889568c79a4d95"

  def test_eip191_hash_matches_viem
    prefixed = SmartWalletHelpers.prefix_message(SIWE_MESSAGE)
    hash = SmartWalletHelpers.bin_to_hex(SmartWalletHelpers.keccak256(prefixed))
    assert_equal EXPECTED_HASH, hash
  end

  def test_message_bytesize
    assert_equal 232, SIWE_MESSAGE.bytesize
  end
end

class ValidatorAbiEncodingTest < Minitest::Test
  # Test vector: ABI-encode (address, bytes32, bytes) matching viem.encodeAbiParameters output.
  # Address: 0x05616f5E0B9a600D4D51DE3D0D24C5D6dD638BE0 (random key, no code on mainnet)
  # Hash and signature verified via viem.

  ADDRESS   = "05616f5e0b9a600d4d51de3d0d24c5d6dd638be0"
  HASH      = "f9e0abaf53d39c5b7e8122276cb46f6cf5b100d32ba23bd095889568c79a4d95"
  SIGNATURE = "ea337e906e34f485e054c5999ae2c97a8d346474633798a5c88fcb3e6a3f3964" \
              "44f685fc1a43a743c54d6037dd6f3c0b516d35229c24fe2a8d03c7783cbc2d2b1c"

  # Expected output from viem.encodeAbiParameters (without 0x prefix)
  EXPECTED_ENCODING =
    "00000000000000000000000005616f5e0b9a600d4d51de3d0d24c5d6dd638be0" \
    "f9e0abaf53d39c5b7e8122276cb46f6cf5b100d32ba23bd095889568c79a4d95" \
    "0000000000000000000000000000000000000000000000000000000000000060" \
    "0000000000000000000000000000000000000000000000000000000000000041" \
    "ea337e906e34f485e054c5999ae2c97a8d346474633798a5c88fcb3e6a3f3964" \
    "44f685fc1a43a743c54d6037dd6f3c0b516d35229c24fe2a8d03c7783cbc2d2b" \
    "1c00000000000000000000000000000000000000000000000000000000000000"

  def test_encoding_matches_viem
    result = SmartWalletHelpers.encode_validator_args(ADDRESS, HASH, SIGNATURE)
    assert_equal EXPECTED_ENCODING, result
  end

  def test_address_left_padded_to_32_bytes
    result = SmartWalletHelpers.encode_validator_args(ADDRESS, HASH, SIGNATURE)
    address_word = result[0, 64]
    # First 24 chars should be zero padding, last 40 chars should be the address
    assert_equal '0' * 24, address_word[0, 24]
    assert_equal ADDRESS, address_word[24, 40]
  end

  def test_hash_occupies_full_word
    result = SmartWalletHelpers.encode_validator_args(ADDRESS, HASH, SIGNATURE)
    hash_word = result[64, 64]
    assert_equal HASH, hash_word
  end

  def test_bytes_offset_is_0x60
    result = SmartWalletHelpers.encode_validator_args(ADDRESS, HASH, SIGNATURE)
    offset_word = result[128, 64]
    assert_equal 96, offset_word.to_i(16), "bytes offset should be 96 (3 × 32)"
  end

  def test_signature_length_is_65
    result = SmartWalletHelpers.encode_validator_args(ADDRESS, HASH, SIGNATURE)
    length_word = result[192, 64]
    assert_equal 65, length_word.to_i(16), "signature length should be 65 bytes"
  end

  def test_signature_data_padded_to_word_boundary
    result = SmartWalletHelpers.encode_validator_args(ADDRESS, HASH, SIGNATURE)
    # 65 bytes = 130 hex chars → padded to 192 hex chars (96 bytes = 3 words)
    sig_data = result[256..]
    assert_equal 0, sig_data.length % 64, "signature data should be padded to 32-byte boundary"
  end

  def test_short_signature
    short_sig = "ab" * 32  # 32 bytes
    result = SmartWalletHelpers.encode_validator_args(ADDRESS, HASH, short_sig)
    length_word = result[192, 64]
    assert_equal 32, length_word.to_i(16)
    # 32 bytes = 64 hex chars → exactly one word, no padding needed
    sig_data = result[256..]
    assert_equal 64, sig_data.length
  end

  def test_long_signature_eip6492
    # EIP-6492 signatures are longer (factory + calldata + inner sig + 32-byte magic suffix)
    long_sig = "ab" * 200  # 200 bytes
    result = SmartWalletHelpers.encode_validator_args(ADDRESS, HASH, long_sig)
    length_word = result[192, 64]
    assert_equal 200, length_word.to_i(16)
    sig_data = result[256..]
    assert_equal 0, sig_data.length % 64, "long sig should be padded to 32-byte boundary"
  end
end

class ValidatorResultParsingTest < Minitest::Test
  def test_valid_padded_to_32_bytes
    hex = "0000000000000000000000000000000000000000000000000000000000000001"
    assert SmartWalletHelpers.parse_validator_result(hex)
  end

  def test_valid_minimal
    assert SmartWalletHelpers.parse_validator_result("01")
  end

  def test_valid_just_one
    assert SmartWalletHelpers.parse_validator_result("1")
  end

  def test_invalid_zero_padded
    hex = "0000000000000000000000000000000000000000000000000000000000000000"
    refute SmartWalletHelpers.parse_validator_result(hex)
  end

  def test_invalid_minimal_zero
    refute SmartWalletHelpers.parse_validator_result("00")
  end

  def test_invalid_nil
    refute SmartWalletHelpers.parse_validator_result(nil)
  end

  def test_invalid_empty_string
    # All zeros stripped → empty string, not "1"
    refute SmartWalletHelpers.parse_validator_result("")
  end

  def test_invalid_other_value
    hex = "0000000000000000000000000000000000000000000000000000000000000002"
    refute SmartWalletHelpers.parse_validator_result(hex)
  end
end

class EthCallParamsTest < Minitest::Test
  # Verify that eth_call parameter construction correctly omits `to` for
  # contract creation (EIP-6492 validator), and includes it for normal calls.

  def test_call_params_with_to
    call_params = { data: "0xdeadbeef" }
    to = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    call_params[:to] = to if to
    assert_equal to, call_params[:to]
    assert_equal "0xdeadbeef", call_params[:data]
  end

  def test_call_params_without_to
    call_params = { data: "0xdeadbeef" }
    to = nil
    call_params[:to] = to if to
    refute call_params.key?(:to), "to should not be present for contract creation"
    assert_equal "0xdeadbeef", call_params[:data]
  end
end
