require 'spec_helper'

describe OmniAuth::Strategies::WSFed, :type => :strategy do
  include OmniAuth::Test::StrategyTestCase

  let(:auth_hash){ last_request.env['omniauth.auth'] }
  let(:wsfed_options) do
    {
        issuer_name:  "http://identity.c4sc.com/trust/",
        issuer:       "https://identity.c4sc.com/issue/wsfed",
        realm:        "http://rp.c4sc/security_realm",
        reply:        "http://rp.c4sc/callback"
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

  describe "OmniAuth DSL method implementation" do

  end

end
