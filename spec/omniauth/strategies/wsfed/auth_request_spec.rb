require 'spec_helper'
require 'erb'

describe OmniAuth::Strategies::WSFed::AuthRequest do

  context :create do

    before(:each) do
      @omniauth_params = {
          issuer_name: "My Organization's IdP",
          issuer: "https://myissuer.com/wsfed",
          realm: "http://myrelyingparty/realm",
          reply: "http://myrelyingparty/callback",
          home_realm: ""
      }
    end

    let :request do
      OmniAuth::Strategies::WSFed::AuthRequest.new.create(@omniauth_params)
    end

    describe "WsFed Auth Request URL" do

      it 'should include the issuer URL followed by WsFed query string params' do
        request.should include "https://myissuer.com/wsfed?"
      end

      it 'should include the WsFed sign-in param (wa)' do
        request.should include 'wa=wsignin1.0'
      end

      it 'should include the url-encoded WsFed security realm param (wtrealm)' do
        request.should include "wtrealm=#{ERB::Util::url_encode(@omniauth_params[:realm])}"
      end

      it 'should include the url-encoded WsFed reply param (wreply)' do
        request.should include "wreply=#{ERB::Util::url_encode(@omniauth_params[:reply])}"
      end

      it 'should include an empty WsFed context param (wctx)' do
        request.should include "wctx=&"
      end

      it 'should include the time at the instant of request creation' do
        time = Time.now.utc
        Time.now.stub(:utc).and_return(time)

        request.should include "wct=#{ERB::Util.url_encode(time)}"
      end

    end

  end

end