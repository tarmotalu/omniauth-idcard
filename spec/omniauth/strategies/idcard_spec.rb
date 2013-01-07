# encoding: utf-8
require 'spec_helper'

describe OmniAuth::Strategies::Idcard do
  subject do
    OmniAuth::Strategies::Idcard.new({})
  end
   
  context '#parse_client_certificate' do
    before do
      @hash = subject.parse_client_certificate(File.read(File.join('spec', 'certificates', "#{ssl_client_cert}.pem")))
    end
    
    let(:ssl_client_cert) { '' }
    
    context 'UCS2' do
      let(:ssl_client_cert) {'UCS2'}
      
      it 'parses lastname' do
        @hash['SN'].should == 'JÄRV'
      end
    end    

    context 'UTF-8' do
      let(:ssl_client_cert) {'UTF8'}
      
      it 'parses firstname' do
        @hash['GN'].should == 'ÜLLE'
      end
    end    
  end
end
