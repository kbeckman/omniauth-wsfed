require 'spec_helper'

describe OmniAuth::Strategies::WSFed, :type => :strategy do
  include OmniAuth::Test::StrategyTestCase

  let(:auth_hash){ last_request.env['omniauth.auth'] }
  let(:wsfed_options) do
    {
      issuer_name: "http://login.myorganization.com/issuer",
      issuer: "https://myissuer.com/wsfed",
      realm: "http://myrelyingparty/realm",
      reply: "http://myrelyingparty/callback",
      home_realm: ""
    }
  end
  let(:strategy) { [OmniAuth::Strategies::WSFed, wsfed_options] }

  describe 'GET /auth/wsfed' do
    before do
      get '/auth/wsfed'
    end

    it 'should get authentication page' do
      last_response.should be_redirect
    end
  end

end
