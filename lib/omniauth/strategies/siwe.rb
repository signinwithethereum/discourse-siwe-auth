require 'siwe'

module OmniAuth
  module Strategies
    class Siwe
      include OmniAuth::Strategy

      # ENS Registry contract address (same on all networks)
      ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"

      option :fields, %i[eth_message eth_signature]

      uid do
        @verified_address
      end

      info do
        ens_name, ens_avatar = resolve_ens(@verified_address)
        display_name = ens_name || @verified_address
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
        siwe_message = ::Siwe::Message.parse(eth_message)

        domain = Discourse.base_url.delete_prefix("#{Discourse.base_protocol}://")
        nonce = session.delete(:nonce)

        @verified_address = siwe_message.address

        config = ::Siwe::Config.new(rpc_url: rpc_url)
        siwe_message.verify!(
          signature: eth_signature,
          domain: domain,
          nonce: nonce,
          config: config
        )

        super
      rescue ::Siwe::Error => e
        fail!(map_failure_reason(e.type))
      end

      private

      # Map Siwe::ErrorType symbols to OmniAuth failure reasons.
      def map_failure_reason(type)
        case type
        when :domain_mismatch, :missing_domain     then :invalid_domain
        when :nonce_mismatch, :missing_nonce       then :invalid_nonce
        when :expired_message                      then :expired_message
        when :not_yet_valid_message                then :invalid_message
        when :invalid_signature,
             :invalid_signature_chain_id,
             :rpc_error                            then :invalid_signature
        else                                            type
        end
      end

      def rpc_url
        url = SiteSetting.siwe_ethereum_rpc_url rescue nil
        url if url && !url.empty?
      end

      # Issue an eth_call via the gem's RPC client. Returns hex without 0x prefix,
      # or nil on transport / RPC failure (used for best-effort ENS resolution).
      def eth_call(to, data, client: nil)
        client ||= ::Siwe::Rpc::HttpClient.new(rpc_url) if rpc_url
        return nil unless client

        client.eth_call(to: to, data: data)
      rescue ::Siwe::Error
        nil
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
        [hex[data_start, length * 2]].pack('H*').force_encoding('UTF-8')
      end

      # Resolve ENS name and avatar for an Ethereum address.
      # Returns [name, avatar_url] or [nil, nil].
      def resolve_ens(address)
        url = rpc_url
        return [nil, nil] unless url

        client = ::Siwe::Rpc::HttpClient.new(url)

        # Step 1: Reverse resolve address → name
        addr_clean = Eth::Util.remove_hex_prefix(address).downcase
        reverse_node = ens_namehash("#{addr_clean}.addr.reverse")

        resolver_hex = eth_call(ENS_REGISTRY, "0x0178b8bf#{reverse_node}", client: client)
        resolver = abi_decode_address(resolver_hex)
        return [nil, nil] unless resolver

        name_hex = eth_call(resolver, "0x691f3431#{reverse_node}", client: client)
        name = abi_decode_string(name_hex)
        return [nil, nil] if name.nil? || name.empty?

        # Step 2: Forward verify — resolve name back to address to prevent spoofing
        forward_node = ens_namehash(name)
        fwd_resolver_hex = eth_call(ENS_REGISTRY, "0x0178b8bf#{forward_node}", client: client)
        fwd_resolver = abi_decode_address(fwd_resolver_hex)
        return [nil, nil] unless fwd_resolver

        addr_hex = eth_call(fwd_resolver, "0x3b3b57de#{forward_node}", client: client)
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
