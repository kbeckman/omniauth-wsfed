require 'omniauth'

module OmniAuth
  module Strategies

    class WsFed
      include OmniAuth::Strategy

      autoload :AuthRequest, 'omniauth/strategies/wsfed/auth_request'

      def request_phase
        request = OmniAuth::Strategies::WsFed::AuthRequest.new
        redirect(request.create(options))
      end

      def callback_phase

      end

    end
  end
end