require 'spec_helper'
require 'erb'

describe OmniAuth::Strategies::WSFed::AuthRequest do

  let(:wsfed_settings) do
    {
        :issuer                     => 'https://c4sc.accesscontrol.windows.net.com/v2/wsfederation',
        :realm                      => 'http://c4sc.com/security_realm',
        :reply                      => 'http://rp.c4sc.com/auth/wsfed',
        :home_realm_discovery_path  => 'auth/home_realm_discovery'
    }
  end

  context 'Initialization' do

    it 'should raise an ArgumentException when strategy_settings are nil or empty' do
      expect { OmniAuth::Strategies::WSFed::AuthRequest.new(nil, {}) }.to raise_error ArgumentError
    end

    it 'should set strategy_settings and args properties when initialized properly' do
      args    = { :whr => 'https://identity.c4sc.com'}
      request = OmniAuth::Strategies::WSFed::AuthRequest.new(wsfed_settings, args)

      request.strategy_settings.should  == wsfed_settings
      request.args.should               == args
    end

  end

  context 'Redirect URL' do

    it 'should equal the :home_realm_discovery path if configured and no :whr argument exists' do
      request = OmniAuth::Strategies::WSFed::AuthRequest.new(wsfed_settings, {})

      request.redirect_url.should == wsfed_settings[:home_realm_discovery_path]
    end

    it 'should equal the wsfed_signin_path if :whr argument exists' do
      args    = { :whr => 'https://identity.c4sc.com'}
      request = OmniAuth::Strategies::WSFed::AuthRequest.new(wsfed_settings, args)

      request.redirect_url.should == request.wsfed_signin_request
    end

    it 'should equal the wsfed_signin_path if :whr argument and :home_realm_discovery_path are missing' do
      wsfed_settings.delete(:home_realm_discovery_path)
      request = OmniAuth::Strategies::WSFed::AuthRequest.new(wsfed_settings, {})

      request.redirect_url.should == request.wsfed_signin_request
    end

  end

  context 'WSFed Signin Request' do

    let :request do
      OmniAuth::Strategies::WSFed::AuthRequest.new(wsfed_settings)
    end

    it 'should include the issuer URL followed by WsFed query string params' do
      request.wsfed_signin_request.should start_with "#{request.strategy_settings[:issuer]}?"
    end

    it 'should include the sign-in param [wa]' do
      request.wsfed_signin_request.should include 'wa=wsignin1.0'
    end

    it 'should include the url-encoded security realm param [wtrealm]' do
      request.wsfed_signin_request.should include "wtrealm=#{ERB::Util::url_encode(request.strategy_settings[:realm])}"
    end

    it 'should include the url-encoded reply param [wreply]' do
      request.wsfed_signin_request.should include "wreply=#{ERB::Util::url_encode(request.strategy_settings[:reply])}"
    end

    it 'should include an empty context param [wctx]' do
      request.wsfed_signin_request.should include "wctx=&"
    end

    it 'should include the request creation instant time param [wtc]' do
      time = Time.now.utc
      Time.now.stub(:utc).and_return(time)

      request.wsfed_signin_request.should include "wct=#{ERB::Util.url_encode(time)}"
    end

    describe 'Url-Encoded Home Realm Parameter [whr]' do

      let(:home_realm) { 'http://identity.c4sc.com/trust' }

      it 'should include [whr] if provided in the options' do
        request = OmniAuth::Strategies::WSFed::AuthRequest.new(wsfed_settings, :whr => home_realm)
        request.wsfed_signin_request.should include "whr=#{ERB::Util::url_encode(home_realm)}"
      end

      it 'should exclude [whr] if ignored in the options' do
        request = OmniAuth::Strategies::WSFed::AuthRequest.new(wsfed_settings, :whr => nil)
        request.wsfed_signin_request.should_not include "whr=#{ERB::Util::url_encode(home_realm)}"
        request.wsfed_signin_request.should_not include 'whr='
      end

    end

  end

end