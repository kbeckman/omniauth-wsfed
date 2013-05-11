require 'spec_helper'

describe OmniAuth::Strategies::WSFed::AuthCallbackValidator do

  let(:auth_callback) { OmniAuth::Strategies::WSFed::AuthCallback.new({}, {})}

  before(:each) do
    @wsfed_settings = {
        :issuer_name  => 'https://identity-wwf.accesscontrol.windows.net/',
        :realm        => 'http://rp.wwf.com/wsfed-sample',
        :id_claim     => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'
    }

    @claims = {
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'                => 'ravishing_rick@wwf.com',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'                        => 'rick.rude',
        'http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider' => 'http://sso.wwf.com'
    }

    auth_callback.stub(:issuer).and_return(@wsfed_settings[:issuer_name])
    auth_callback.stub(:audience).and_return(@wsfed_settings[:realm])
    auth_callback.stub(:claims).and_return(@claims)
    auth_callback.stub(:name_id).and_return(@claims[@wsfed_settings[:id_claim]])
    auth_callback.stub(:created_at).and_return(Time.now.utc - 1) # 1 second ago
    auth_callback.stub(:expires_at).and_return(Time.now.utc + 300) # 5 minutes from now
  end

  context 'with a Valid AuthN Token Response' do

    it 'should pass validation' do
      validator = described_class.new(auth_callback, @wsfed_settings)

      validator.validate!.should == true
    end

  end

  context 'with an Invalid AuthN Token Response' do

    context 'having invalid issuer' do

      before(:each) do
        auth_callback.stub(:issuer).and_return('https://c4sc-federation-nomatch.accesscontrol.windows.net/')
        @validator = described_class.new(auth_callback, @wsfed_settings)
      end

      it 'validate_issuer! should throw an exception' do
        lambda { @validator.validate_issuer! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                                  OmniAuth::Strategies::WSFed::AuthCallbackValidator::ISSUER_MISMATCH
      end

      it 'validate! should throw an exception' do
        lambda { @validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                           OmniAuth::Strategies::WSFed::AuthCallbackValidator::ISSUER_MISMATCH
      end

    end

    context 'having invalid realm/audience' do

      before(:each) do
        auth_callback.stub(:audience).and_return('http://rp.c4sc.com/wsfed-sample-nomatch')
        @validator = described_class.new(auth_callback, @wsfed_settings)
      end

      it 'validate_audience! should throw an exception' do
        lambda { @validator.validate_audience! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                                    OmniAuth::Strategies::WSFed::AuthCallbackValidator::AUDIENCE_MISMATCH
      end

      it 'validate! should throw an exception' do
        lambda { @validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                           OmniAuth::Strategies::WSFed::AuthCallbackValidator::AUDIENCE_MISMATCH
      end

    end

    context 'having invalid (limit exceeded) expires_at' do

      before(:each) do
        auth_callback.stub(:expires_at).and_return(Time.now.utc - 1)
        @validator = described_class.new(auth_callback, @wsfed_settings)
      end

      it 'validate_token_expiration! should throw an exception' do
        lambda { @validator.validate_token_expiration! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                                            OmniAuth::Strategies::WSFed::AuthCallbackValidator::TOKEN_EXPIRED
      end

      it 'validate! should throw an exception' do
        lambda { @validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                           OmniAuth::Strategies::WSFed::AuthCallbackValidator::TOKEN_EXPIRED
      end

    end

    context 'having a nil or empty claims hash' do

      it 'validate_claims! and validate! should each throw an exception' do
        [nil, {}].each do |val|
          auth_callback.stub(:claims).and_return(val)

          validator = described_class.new(auth_callback, @wsfed_settings)

          lambda { validator.validate_claims! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                                   OmniAuth::Strategies::WSFed::AuthCallbackValidator::NO_CLAIMS

          lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                            OmniAuth::Strategies::WSFed::AuthCallbackValidator::NO_CLAIMS
        end
      end
    end

    context 'having a nil or empty uid value' do

      it 'should throw an exception when the name_id is empty or nil' do
        [nil, ""].each do |val|
          auth_callback.stub(:name_id).and_return(val)

          validator = described_class.new(auth_callback, @wsfed_settings)

          lambda { validator.validate_uid! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                                OmniAuth::Strategies::WSFed::AuthCallbackValidator::NO_USER_IDENTIFIER

          lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                            OmniAuth::Strategies::WSFed::AuthCallbackValidator::NO_USER_IDENTIFIER
        end
      end

    end

  end
end
