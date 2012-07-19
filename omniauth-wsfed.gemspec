# -*- encoding: utf-8 -*-
require File.expand_path('../lib/omniauth-wsfed/version', __FILE__)

Gem::Specification.new do |gem|

  gem.name          = "omniauth-wsfed"
  gem.version       = OmniAuth::WSFed::VERSION
  gem.description   = %q{A WS-Federation and WS-Trust strategy for OmniAuth.}
  gem.summary       = %q{A WS-Federation and WS-Trust strategy for OmniAuth.}

  gem.authors       = ["kbeckman"]
  gem.email         = ["kbeckman.c4sc@gmail.com"]
  gem.homepage      = "https://github.com/kbeckman/omniauth-wsfed"

  gem.add_runtime_dependency 'omniauth', '~> 1.1.0'
  gem.add_runtime_dependency 'xmlcanonicalizer', '0.1.1'
  gem.add_runtime_dependency 'typhoeus', '~> 0.4.2'

  gem.add_development_dependency 'rspec', '~> 2.10.0'
  gem.add_development_dependency 'rake', '~> 0.9.2'
  gem.add_development_dependency 'rack-test', '~> 0.6.1'

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

end
