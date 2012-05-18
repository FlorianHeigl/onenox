#!/usr/bin/env ruby 

require 'xmlrpc/client'

##############################################################################
## Environment Configuration
###############################################################################
ONE_LOCATION=ENV["ONE_LOCATION"]

if !ONE_LOCATION
    RUBY_LIB_LOCATION="/usr/lib/one/ruby"
else
    RUBY_LIB_LOCATION=ONE_LOCATION+"/lib/ruby"
end

$: << RUBY_LIB_LOCATION
###############################################################################

xmlrpc_server = 'http://localhost:8000/RPC2'

# Get arguments 
elastic_ip  = ARGV[0]

# Create XML-RPC Connection 
server = XMLRPC::Client.new2(xmlrpc_server)

# Tell OpenFlow Controller to disassociate elastic IP address 
result = server.call("DisassociateAddress", elastic_ip)

