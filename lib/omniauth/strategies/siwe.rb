require 'net/http'
require 'json'

module OmniAuth
  module Strategies
    class Siwe
      include OmniAuth::Strategy

      # EIP-1271 magic value returned by isValidSignature
      EIP1271_MAGIC_VALUE = "1626ba7e"

      option :fields, %i[eth_message eth_account eth_signature eth_name]
      option :uid_field, :eth_account

      uid do
        request.params[options.uid_field.to_s]
      end

      info do
        eth_name = request.params['eth_name']
        display_name = eth_name.to_s.empty? ? request.params[options.uid_field.to_s] : eth_name
        {
          nickname: display_name,
          name: display_name,
          image: request.params['eth_avatar']
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

      def eip1271_valid?(siwe_message, signature)
        rpc_url = SiteSetting.siwe_ethereum_rpc_url rescue nil
        return false if rpc_url.nil? || rpc_url.empty?

        # Hash the message the same way personal_sign does (EIP-191)
        prefixed = Eth::Signature.prefix_message(siwe_message.prepare_message)
        message_hash = Eth::Util.bin_to_hex(Eth::Util.keccak256(prefixed))

        # ABI-encode isValidSignature(bytes32 hash, bytes signature)
        # Function selector: 0x1626ba7e
        hash_param = message_hash.rjust(64, '0')
        sig_bytes = Eth::Util.remove_hex_prefix(signature)
        # offset to bytes data (64 bytes = 0x40)
        offset = "0000000000000000000000000000000000000000000000000000000000000040"
        # length of signature bytes
        sig_length = (sig_bytes.length / 2).to_s(16).rjust(64, '0')
        # signature data padded to 32-byte boundary
        sig_padded = sig_bytes.ljust(((sig_bytes.length + 63) / 64) * 64, '0')

        data = "0x1626ba7e#{hash_param}#{offset}#{sig_length}#{sig_padded}"
        address = siwe_message.address

        # JSON-RPC eth_call
        uri = URI(rpc_url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = 10
        http.read_timeout = 10
        req = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path, 'Content-Type' => 'application/json')
        req.body = {
          jsonrpc: "2.0",
          method: "eth_call",
          params: [{ to: address, data: data }, "latest"],
          id: 1
        }.to_json

        response = http.request(req)
        result = JSON.parse(response.body)

        return false if result['error'] || result['result'].nil?

        # EIP-1271: returned value is bytes32, magic value is left-aligned
        Eth::Util.remove_hex_prefix(result['result']).downcase[0, 8] == EIP1271_MAGIC_VALUE
      rescue StandardError
        false
      end
    end
  end
end
