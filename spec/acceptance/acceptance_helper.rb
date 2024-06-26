require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'capybara/rspec'

# Put your acceptance spec helpers inside /spec/acceptance/support
Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each { |f| require f }

RSpec.configure do |config|
  config.include Rails.application.routes.url_helpers, type: :request
end
