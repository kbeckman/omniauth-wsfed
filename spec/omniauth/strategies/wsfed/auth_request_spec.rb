require 'spec_helper'
require 'erb'

describe OmniAuth::Strategies::WSFed::AuthRequest do

  context 'Valid Request' do

    before(:each) do
      @omniauth_params = {
          issuer_name:  "My Organization's IdP",
          issuer:       "https://my.issuer.com/issue/wsfed",
          realm:        "http://my.organization/security_realm",
          reply:        "http://my.relyingparty/callback"
      }
    end

    let :request do
      OmniAuth::Strategies::WSFed::AuthRequest.new.create(@omniauth_params)
    end

    describe 'WsFed Auth Request URL' do

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

        it 'should be included if present in settings hash (whr)' do
          @omniauth_params[:home_realm] = 'https://user.organization/realm'

          request.should include "whr=#{ERB::Util::url_encode(@omniauth_params[:home_realm])}"
        end

        it 'should be excluded if missing in settings hash (whr)' do
          request.should_not include "whr=#{ERB::Util::url_encode(@omniauth_params[:home_realm])}"
          request.should_not include "whr="
        end

        it 'should take home realm from the request over the wsfed strategy settings if both are present' do
          realm_from_querystr           = "https://home.realm/from-request"
          realm_from_settings           = "https://home.realm/from-settings"
          @omniauth_params[:home_realm] = realm_from_settings

          request = OmniAuth::Strategies::WSFed::AuthRequest.new.create(@omniauth_params, :whr => realm_from_settings)

          request.should include "whr=#{ERB::Util::url_encode(realm_from_settings)}"
          request.should_not include "whr=#{ERB::Util::url_encode(realm_from_querystr)}"
        end

      end

    end

  end

end