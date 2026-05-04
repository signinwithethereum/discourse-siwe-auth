# frozen_string_literal: true

require 'siwe'
module DiscourseSiwe
  class AuthController < ::ApplicationController
    skip_before_action :check_xhr, only: %i[index]
    skip_before_action :redirect_to_login_if_required, only: %i[index message]

    def index
      raise ApplicationController::RenderEmpty
    end

    def message
      eth_account = params[:eth_account]
      chain_id = params[:chain_id]

      unless eth_account.present? && eth_account.match?(/\A0x[0-9a-fA-F]{40}\z/)
        return render json: { error: "Invalid Ethereum address" }, status: 400
      end

      unless chain_id.present? && chain_id.match?(/\A[1-9][0-9]*\z/)
        return render json: { error: "Invalid chain ID" }, status: 400
      end

      now = Time.now.utc
      domain = Discourse.base_url.delete_prefix("#{Discourse.base_protocol}://")
      message = Siwe::Message.new(
        domain: domain,
        address: eth_account,
        uri: Discourse.base_url,
        version: "1",
        chain_id: chain_id.to_i,
        nonce: Siwe.generate_nonce,
        issued_at: now.iso8601,
        expiration_time: (now + 300).iso8601,
        statement: SiteSetting.siwe_statement
      )
      session[:nonce] = message.nonce

      render json: { message: message.prepare_message }
    end
  end
end
