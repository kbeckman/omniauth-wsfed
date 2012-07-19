require 'spec_helper'
require 'erb'

describe AzureACS::IdPFeed do

describe "Initialization" do

  context "with Invalid Context" do

    it "should raise an exception when IdP JSON feed URL is nil" do
      expect { described_class.new(nil) }.to raise_error ArgumentError
    end

  end

end

end