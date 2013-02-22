# -*- encoding: utf-8 -*-
require File.expand_path('../lib/omniauth-wsfed/version', __FILE__)

Gem::Specification.new do |gem|

  gem.name          = 'omniauth-wsfed'
  gem.version       = OmniAuth::WSFed::VERSION
  gem.summary       = %q{A WS-Federation + WS-Trust strategy for OmniAuth.}
  gem.description   = %q{OmniAuth WS-Federation strategy enabling integration with Windows Azure Access Control Service (ACS), Active Directory Federation Services (ADFS) 2.0, custom Identity Providers built with Windows Identity Foundation (WIF) or any other Identity Provider supporting the WS-Federation protocol.}

  gem.authors       = ['Keith Beckman']
  gem.email         = ['kbeckman.c4sc@gmail.com']
  gem.homepage      = 'https://github.com/kbeckman/omniauth-wsfed'

  gem.add_runtime_dependency 'omniauth', '~> 1.1.0'
  gem.add_runtime_dependency 'xmlcanonicalizer', '0.1.1'

  gem.add_development_dependency 'rspec', '>= 2.12.0'
  gem.add_development_dependency 'rake', '>= 10.0.3'
  gem.add_development_dependency 'rack-test', '>= 0.6.2'

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ['lib']

end
