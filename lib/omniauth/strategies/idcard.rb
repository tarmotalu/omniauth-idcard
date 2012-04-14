require 'omniauth-oauth'
require 'openssl'

module OmniAuth
  module Strategies
    class Idcard < OmniAuth::Strategies::OAuth
      
      option :name, 'idcard'
      option :logger, nil
      
      uid { @user_data['serialNumber'] }
      
      info do
        {
          'uid' => uid,
          'user_info' => {
            'personal_code' => @user_data['serialNumber'],
            'first_name' => @user_data['GN'],
            'last_name' => @user_data['SN'],
            'name' => "#{@user_data['GN']} #{@user_data['SN']}"
          }
        }
      end
      
      def request_phase
        if @env['SSL_CLIENT_CERT']
          debug "Start authentication with ID-Card. Got certificate:"
          debug @env['SSL_CLIENT_CERT']
          
          @user_data = parse_client_certificate(@env['SSL_CLIENT_CERT'])
          @env['REQUEST_METHOD'] = 'GET'
          @env['omniauth.auth'] = info
          @env['PATH_INFO'] = "#{OmniAuth.config.path_prefix}/#{name}/callback"
          
          debug "ID-Card request was authenticated successfully. User data: #{info.inspect}"
          
          call_app!
        else
          debug "Could not authenticate with ID-Card. Certificate is missing."
          fail!(:client_certificate_missing)
        end
      end
      
      def parse_client_certificate(data)
        cert = OpenSSL::X509::Certificate.new(data)
        subject_dn = cert.subject.to_s.scan(/./mu) {|s| s[0].chr}
        
        debug "Subject DN: #{subject_dn}"
        
        subject_dn.split('/').inject(Hash.new) do |memo, part|
          item = part.split('=')
          memo[item.first] = item.last
          memo
        end
      end

      def callback_phase
        fail!(:invalid_credentials)
      end

      private 
      
      def debug(message)
        options[:logger].debug("#{Time.now} #{message}") if options[:logger]
      end
    end
  end
end