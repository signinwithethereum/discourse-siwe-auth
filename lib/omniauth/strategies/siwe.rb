require 'net/http'
require 'json'

module OmniAuth
  module Strategies
    class Siwe
      include OmniAuth::Strategy

      # EIP-1271 magic value returned by isValidSignature
      EIP1271_MAGIC_VALUE = "1626ba7e"

      # ENS Registry contract address (same on all networks)
      ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"

      option :fields, %i[eth_message eth_account eth_signature]
      option :uid_field, :eth_account

      uid do
        request.params[options.uid_field.to_s]
      end

      info do
        address = request.params[options.uid_field.to_s]
        ens_name, ens_avatar = resolve_ens(address)
        display_name = ens_name || address
        {
          nickname: display_name,
          name: display_name,
          image: ens_avatar
        }
      end

      def request_phase
        query_string = env['QUERY_STRING']
        redirect "/discourse-siwe/auth?#{query_string}"
      end

      def callback_phase
        eth_message_crlf = request.params['eth_message']
        eth_message = eth_message_crlf.encode(eth_message_crlf.encoding, universal_newline: true)
        eth_signature = request.params['eth_signature']
        siwe_message = ::Siwe::Message.from_message(eth_message)

        domain = Discourse.base_url
        domain.slice!("#{Discourse.base_protocol}://")
        if siwe_message.domain != domain
          return fail!("Invalid domain")
        end

        if siwe_message.nonce != session[:nonce]
          return fail!("Invalid nonce")
        end

        failure_reason = nil
        begin
          siwe_message.validate(eth_signature)
        rescue ::Siwe::ExpiredMessage
          failure_reason = :expired_message
        rescue ::Siwe::NotValidMessage
          failure_reason = :invalid_message
        rescue ::Siwe::InvalidSignature
          # EOA verification failed — try EIP-1271 for smart contract wallets (e.g. SAFE)
          unless eip1271_valid?(siwe_message, eth_signature)
            failure_reason = :invalid_signature
          end
        end

        return fail!(failure_reason) if failure_reason

        super
      end

      private

      def rpc_url
        url = SiteSetting.siwe_ethereum_rpc_url rescue nil
        url if url && !url.empty?
      end

      # Generic JSON-RPC eth_call. Returns hex result without 0x prefix, or nil.
      def eth_call(to, data)
        return nil unless rpc_url

        uri = URI(rpc_url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = 10
        http.read_timeout = 10
        req = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path, 'Content-Type' => 'application/json')
        req.body = {
          jsonrpc: "2.0",
          method: "eth_call",
          params: [{ to: to, data: data }, "latest"],
          id: 1
        }.to_json

        response = http.request(req)
        result = JSON.parse(response.body)
        return nil if result['error'] || result['result'].nil? || result['result'] == '0x'

        Eth::Util.remove_hex_prefix(result['result'])
      rescue StandardError
        nil
      end

      # EIP-1271 smart contract signature verification
      def eip1271_valid?(siwe_message, signature)
        return false unless rpc_url

        # Hash the message the same way personal_sign does (EIP-191)
        prefixed = Eth::Signature.prefix_message(siwe_message.prepare_message)
        message_hash = Eth::Util.bin_to_hex(Eth::Util.keccak256(prefixed))

        # ABI-encode isValidSignature(bytes32 hash, bytes signature)
        hash_param = message_hash.rjust(64, '0')
        sig_bytes = Eth::Util.remove_hex_prefix(signature)
        offset = "0000000000000000000000000000000000000000000000000000000000000040"
        sig_length = (sig_bytes.length / 2).to_s(16).rjust(64, '0')
        sig_padded = sig_bytes.ljust(((sig_bytes.length + 63) / 64) * 64, '0')

        data = "0x1626ba7e#{hash_param}#{offset}#{sig_length}#{sig_padded}"
        result = eth_call(siwe_message.address, data)
        return false if result.nil?

        result.downcase[0, 8] == EIP1271_MAGIC_VALUE
      end

      # Compute ENS namehash for a domain name
      def ens_namehash(name)
        node = "\x00" * 32
        unless name.nil? || name.empty?
          name.split('.').reverse.each do |label|
            label_hash = Eth::Util.keccak256(label)
            node = Eth::Util.keccak256(node + label_hash)
          end
        end
        Eth::Util.bin_to_hex(node)
      end

      # Decode an ABI-encoded address return value
      def abi_decode_address(hex)
        return nil if hex.nil? || hex.length < 40
        address = hex[-40, 40]
        return nil if address == '0' * 40
        "0x#{address}"
      end

      # Decode an ABI-encoded string return value
      def abi_decode_string(hex)
        return nil if hex.nil? || hex.length < 128
        offset = hex[0, 64].to_i(16) * 2
        length = hex[offset, 64].to_i(16)
        return '' if length == 0
        data_start = offset + 64
        return nil if hex.length < data_start + length * 2
        [hex[data_start, length * 2]].pack('H*')
      end

      # Resolve ENS name and avatar for an Ethereum address.
      # Returns [name, avatar_url] or [nil, nil].
      def resolve_ens(address)
        return [nil, nil] unless rpc_url

        # Step 1: Reverse resolve address → name
        addr_clean = Eth::Util.remove_hex_prefix(address).downcase
        reverse_node = ens_namehash("#{addr_clean}.addr.reverse")

        # Get resolver for the reverse node from ENS registry
        resolver_hex = eth_call(ENS_REGISTRY, "0x0178b8bf#{reverse_node}")
        resolver = abi_decode_address(resolver_hex)
        return [nil, nil] unless resolver

        # Get the name from the reverse resolver
        name_hex = eth_call(resolver, "0x691f3431#{reverse_node}")
        name = abi_decode_string(name_hex)
        return [nil, nil] if name.nil? || name.empty?

        # Step 2: Forward verify — resolve name back to address to prevent spoofing
        forward_node = ens_namehash(name)
        fwd_resolver_hex = eth_call(ENS_REGISTRY, "0x0178b8bf#{forward_node}")
        fwd_resolver = abi_decode_address(fwd_resolver_hex)
        return [nil, nil] unless fwd_resolver

        addr_hex = eth_call(fwd_resolver, "0x3b3b57de#{forward_node}")
        resolved_addr = abi_decode_address(addr_hex)
        return [nil, nil] unless resolved_addr&.downcase == address.downcase

        [name, ens_avatar_url(name)]
      rescue StandardError
        [nil, nil]
      end

      # Returns the ENS metadata avatar URL if it exists, nil otherwise.
      def ens_avatar_url(name)
        url = "https://metadata.ens.domains/mainnet/avatar/#{name}"
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.open_timeout = 5
        http.read_timeout = 5
        response = http.request(Net::HTTP::Head.new(uri.path))
        response.code.to_i == 200 ? url : nil
      rescue StandardError
        nil
      end
    end
  end
end
