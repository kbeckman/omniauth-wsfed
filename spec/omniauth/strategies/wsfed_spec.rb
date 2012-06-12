require 'spec_helper'

describe OmniAuth::Strategies::WSFed, :type => :strategy do
  include OmniAuth::Test::StrategyTestCase

  let(:auth_hash){ last_request.env['omniauth.auth'] }
  let(:wsfed_options) do
    {
        issuer_name:  "My Organization's IdP",
        issuer:       "https://my.issuer.com/issue/wsfed",
        realm:        "http://my.organization/security_realm",
        reply:        "http://my.relyingparty/callback"
    }
  end
  let(:strategy) { [OmniAuth::Strategies::WSFed, wsfed_options] }

  describe 'GET /auth/wsfed' do

    it 'should redirect to the IdP issue URL for authentication' do
      get '/auth/wsfed'

      last_response.should be_redirect
      last_response.location.should include wsfed_options[:issuer]
    end

  end

end
