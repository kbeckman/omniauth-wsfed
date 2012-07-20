require 'spec_helper'
require 'erb'

describe OmniAuth::Strategies::WSFed::AuthRequest do

  context 'Valid Request' do

    before(:each) do
      @omniauth_params = {
          issuer:       "https://c4sc.accesscontrol.windows.net.com/v2/wsfederation",
          realm:        "http://c4sc.com/security_realm",
          reply:        "http://rp.c4sc.com/auth/wsfed"
      }
    end

    describe 'WsFed Auth Request URL' do

      let :request do
        OmniAuth::Strategies::WSFed::AuthRequest.new.create(@omniauth_params)
      end

      it 'should include the issuer URL followed by WsFed query string params' do
        request.should start_with "#{@omniauth_params[:issuer]}?"
      end

      it 'should include the sign-in param [wa]' do
        request.should include 'wa=wsignin1.0'
      end

      it 'should include the url-encoded security realm param [wtrealm]' do
        request.should include "wtrealm=#{ERB::Util::url_encode(@omniauth_params[:realm])}"
      end

      it 'should include the url-encoded reply param [wreply]' do
        request.should include "wreply=#{ERB::Util::url_encode(@omniauth_params[:reply])}"
      end

      it 'should include an empty context param [wctx]' do
        request.should include "wctx=&"
      end

      it 'should include the request creation instant time param [wtc]' do
        time = Time.now.utc
        Time.now.stub(:utc).and_return(time)

        request.should include "wct=#{ERB::Util.url_encode(time)}"
      end

      describe 'Url-Encoded Home Realm Parameter [whr]' do

        before(:each) do
          @home_realm = "http://identity.c4sc.com/trust"
        end

        it 'should include [whr] if provided in the options' do
          request = OmniAuth::Strategies::WSFed::AuthRequest.new.create(@omniauth_params, :whr => @home_realm)
          request.should include "whr=#{ERB::Util::url_encode(@home_realm)}"
        end

        it 'should exclude [whr] if ignored in the options' do
          request = OmniAuth::Strategies::WSFed::AuthRequest.new.create(@omniauth_params, :whr => nil)
          request.should_not include "whr=#{ERB::Util::url_encode(@home_realm)}"
          request.should_not include "whr="
        end

      end

    end

  end

end