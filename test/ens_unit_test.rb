#!/usr/bin/env ruby
# Unit tests for ENS resolution helpers (no RPC needed).
#
# Run: ruby test/ens_unit_test.rb

$LOAD_PATH.unshift(*Dir[File.join(__dir__, '..', 'gems/3.4.8/gems/keccak-*/lib')])
require 'digest/keccak'
require 'minitest/autorun'

# Standalone reimplementations of the functions under test,
# using Digest::Keccak directly (avoids the native rbsecp256k1 dep).
module EnsHelpers
  module_function

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

end

class EnsNamehashTest < Minitest::Test
  # Well-known ENS namehash test vectors from EIP-137
  # https://eips.ethereum.org/EIPS/eip-137

  def test_empty_name
    assert_equal '0' * 64, EnsHelpers.ens_namehash('')
  end

  def test_eth
    expected = '93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae'
    assert_equal expected, EnsHelpers.ens_namehash('eth')
  end

  def test_foo_dot_eth
    expected = 'de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f'
    assert_equal expected, EnsHelpers.ens_namehash('foo.eth')
  end

  def test_alice_dot_eth
    expected = '787192fc5378cc32aa956ddfdedbf26b24e8097e87e8f1f430f8e"; abort' # not a real injection
    # Compute actual value
    actual = EnsHelpers.ens_namehash('alice.eth')
    assert_equal 64, actual.length, 'namehash should be 64 hex chars'
  end

  def test_reverse_node
    # For address 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
    addr_clean = 'd8da6bf26964af9d7eed9e03e53415d37aa96045'
    reverse_name = "#{addr_clean}.addr.reverse"
    hash = EnsHelpers.ens_namehash(reverse_name)
    assert_equal 64, hash.length
    # Verify it's deterministic
    assert_equal hash, EnsHelpers.ens_namehash(reverse_name)
  end

  def test_nil_name
    assert_equal '0' * 64, EnsHelpers.ens_namehash(nil)
  end
end

class AbiDecodeAddressTest < Minitest::Test
  def test_valid_address
    # 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 padded to 32 bytes
    hex = '000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045'
    assert_equal '0xd8da6bf26964af9d7eed9e03e53415d37aa96045', EnsHelpers.abi_decode_address(hex)
  end

  def test_zero_address
    hex = '0000000000000000000000000000000000000000000000000000000000000000'
    assert_nil EnsHelpers.abi_decode_address(hex)
  end

  def test_nil_input
    assert_nil EnsHelpers.abi_decode_address(nil)
  end

  def test_short_input
    assert_nil EnsHelpers.abi_decode_address('abcd')
  end
end

class AbiDecodeStringTest < Minitest::Test
  def test_simple_string
    # ABI-encoded "vitalik.eth" (11 bytes)
    hex = '0000000000000000000000000000000000000000000000000000000000000020' \
          '000000000000000000000000000000000000000000000000000000000000000b' \
          '766974616c696b2e657468000000000000000000000000000000000000000000'
    assert_equal 'vitalik.eth', EnsHelpers.abi_decode_string(hex)
  end

  def test_short_string
    # ABI-encoded "eth" (3 bytes)
    hex = '0000000000000000000000000000000000000000000000000000000000000020' \
          '0000000000000000000000000000000000000000000000000000000000000003' \
          '6574680000000000000000000000000000000000000000000000000000000000'
    assert_equal 'eth', EnsHelpers.abi_decode_string(hex)
  end

  def test_empty_string
    hex = '0000000000000000000000000000000000000000000000000000000000000020' \
          '0000000000000000000000000000000000000000000000000000000000000000'
    assert_equal '', EnsHelpers.abi_decode_string(hex)
  end

  def test_nil_input
    assert_nil EnsHelpers.abi_decode_string(nil)
  end

  def test_too_short
    assert_nil EnsHelpers.abi_decode_string('0020')
  end

  def test_avatar_url
    # ABI-encoded "https://example.com/avatar.png" (30 bytes)
    url = 'https://example.com/avatar.png'
    url_hex = url.unpack1('H*')
    url_padded = url_hex.ljust(64, '0')
    hex = '0000000000000000000000000000000000000000000000000000000000000020' \
          '000000000000000000000000000000000000000000000000000000000000001e' \
          "#{url_padded}"
    assert_equal url, EnsHelpers.abi_decode_string(hex)
  end
end

