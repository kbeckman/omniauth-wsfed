module AzureACS

  class IdPFeed

    def initialize(idp_json_feed_url)
      raise ArgumentError.new("Azure ACS JSON feed URL cannot be null.") if idp_json_feed_url.nil?
      @json_feed_url = idp_json_feed_url
    end

    def identity_providers
      @json_feed ||= Typhoeus::Request.get(@json_feed_url).body
    end

  end

end