#!/usr/bin/env ruby
# Integration tests for the installed SIWE gem (no RPC needed).
#
# Run after the plugin gems have been installed:
#   ruby test/siwe_unit_test.rb

require "minitest/autorun"

require_relative "test_helper"
PluginTestGems.activate("keccak", "1.3.3")
PluginTestGems.activate("siwe-rb", "0.3.0")
require "siwe"

class SiweGemTest < Minitest::Test
  EXAMPLE_SIGNATURE = "0x7fcf011b4dff0a6024ce6cea93dcd0ebc4592f43e7685e174d4d3d4a1f942ed7" \
                      "5bbf5358841924dc8e1b261f750dfec5dbcc0aad9a3d9439f1e5c4d59d7d98a81c"
  TALLY_SIGNATURE = "0x8c46b6eb8505939892d8e9b075f89f8277321b17b993151f37810cdda38cce6f" \
                    "4a85909d2b53e6a14629c74c0ac38bf4becde78ee5b2529812bf6cceaf7b2a2501"

  def test_verifies_official_eip_4361_vector
    message = Siwe::Message.new(
      domain: "siwe.xyz",
      address: "0xAE9aA90F1a627c7a20783AF9e8747fCFEDEFAd03",
      statement: "Sign In with Ethereum Example Statement",
      uri: "https://siwe.xyz",
      version: "1",
      nonce: "bTyXgcQxn2htgkjJn",
      issued_at: "2022-01-27T17:09:38.578Z",
      chain_id: 1,
      expiration_time: "2100-01-07T14:31:43.952Z"
    )

    assert_same message,
                message.verify!(
                  signature: EXAMPLE_SIGNATURE,
                  domain: "siwe.xyz",
                  nonce: "bTyXgcQxn2htgkjJn"
                )
  end

  def test_accepts_zero_based_recovery_byte
    message = Siwe::Message.new(
      domain: "www.tally.xyz",
      address: "0xc95EB884FE852e241D409234bfC7045CB9E31BD7",
      statement: "Sign in with Ethereum to Tally",
      uri: "https://tally.xyz",
      version: "1",
      chain_id: 1,
      nonce: "15050747",
      issued_at: "2022-06-30T14:08:51.382Z"
    )

    assert_same message,
                message.verify!(
                  signature: TALLY_SIGNATURE,
                  domain: "www.tally.xyz",
                  nonce: "15050747"
                )
  end

  def test_does_not_load_eth_or_rbsecp256k1
    refute Gem.loaded_specs.key?("eth")
    refute Gem.loaded_specs.key?("rbsecp256k1")
  end
end
