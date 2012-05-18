#!/usr/bin/env ruby 

require 'base64'
require 'rexml/document'
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

# XML-RPC Server for OpenFlow Controller
xmlrpc_server = 'http://localhost:8000/RPC2'

# Get Arguments 
elastic_ip  = ARGV[0]
private_ip  = ARGV[1]
vm_template = ARGV[2] 

# Decode VNET Template
vm_xml = Base64::decode64(vm_template)
vm_root = REXML::Document.new(vm_xml).root

# Fetch VNET values from template XML
vlan_id  = vm_root.get_text('VLAN_ID').value
vlan_gw  = vm_root.get_text('TEMPLATE/GATEWAY').value 

# Need to find MAC addess of Elastic IP
private_mac = nil 
vm_root.elements.each("LEASES/LEASE") do |eip|
    if eip.get_text('IP').value == elastic_ip
        private_mac = eip.get_text('MAC').value
        break
    end
end

if private_mac == nil
    puts "Cannot find MAC address of Elastic IP"
    exit(status=FALSE)
end

# Create XML-RPC Connection 
server = XMLRPC::Client.new2(xmlrpc_server)

# Tell OpenFlow Controller to associate elastic IP address 
result = server.call("AssociateAddress", elastic_ip, private_ip, private_mac, ovs_dpid, ovs_port, vlan_id, vlan_gw)

