import httplib
import json
import socket
import threading
import time
import pdb
import base64
from sets import Set
from oslo.config import cfg

from neutron.openstack.common import log as logging
from neutron.openstack.common import lockutils
from neutron.common import exceptions
import novaclient.v1_1.client as nvclient
from keystoneclient.v2_0 import client
from neutron.openstack.common import loopingcall
from neutron.plugins.ml2 import driver_api as api
from neutron.db import models_v2
from neutron.db import api as db
from neutron.plugins.ml2 import models
from neutron.plugins.ml2.drivers.dell import config


# The following are used to invoke the API on the external controller
HOST_URI = "/sdnc/v1/hosts/%s@%s@%s"
HOST_ENDPOINT_URI = "/sdnc/v1/hosts/%s@%s@%s/endpoints/%s@%s@%s" 
NETWORK_URI = "/sdnc/v1/networks/%s@%s@%s"
PORT_URI = "/sdnc/v1/endpoints/%s@%s@%s"
PROVIDER_PORT_URI = "/sdnc/v1/endpoints/%s@%s"
PORT_DEPLOY_URI = "/sdnc/v1/networks/%s@%s@%s/endpoints/%s@%s@%s"
PROVIDER_URI = "/sdnc/v1/providers/%s"
TENANT_URI = "/sdnc/v1/tenants/%s@%s"
CONTROLLER_TIME_URI = "/debugsdnc/v1/startuptime"
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [0, 301, 302, 303, 400, 401, 403, 404, 500, 501, 502, 503,
                 504, 505]
SYNTAX_ERROR_MESSAGE = 'Syntax error in server config file, aborting plugin'
BASE_URI = '/sdnc/v1'
ORCHESTRATION_SERVICE_ID = 'neutron v2.0'
METADATA_SERVER_IP = '169.254.169.254'
LOG = logging.getLogger(__name__)

provider_id = 9
class RemoteRestError(exceptions.NeutronException):
    def __init__(self, message):
        if message is None:
            message = "None"
        self.message = _("Error in REST call to vulcan network "
                         "controller") + ": " + message
        super(RemoteRestError, self).__init__()


class Server(object):
    """REST server proxy to a network controller."""

    def __init__(self):
        global provider_id
        self.server = cfg.CONF.ml2_dell.controller_ip
        self.port = cfg.CONF.ml2_dell.controller_port
        provider_id = cfg.CONF.ml2_dell.provider_id
        self.username = cfg.CONF.ml2_dell.username
        self.password = cfg.CONF.ml2_dell.password
        self.success_codes = SUCCESS_CODES
        self.timeout = 10

    @lockutils.synchronized('rest_call', 'dell-',True)
    def rest_call(self, action, resource, data, headers):
        uri = resource
        body = json.dumps(data)
        if not headers:
            headers = {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'  
        headers["Authorization"] = "Basic {0}".format(base64.b64encode("{0}:{1}".format(self.username, self.password)))  
        LOG.debug(_("ServerProxy: resource=%(resource)s, data=%(data)r, "
                    "headers=%(headers)r"), locals())

        conn = httplib.HTTPConnection(
            self.server, self.port, timeout=self.timeout)
        if conn is None:
            LOG.error(_('ServerProxy: Could not establish HTTP '
                        'connection'))
            return 0, None, None, None

        try:
            conn.request(action, uri, body, headers)
            response = conn.getresponse()
            respstr = response.read()
            respdata = respstr
            if response.status in self.success_codes:
                try:
                    respdata = json.loads(respstr)
                except ValueError:
                    # response was not JSON, ignore the exception
                    pass
            ret = (response.status, response.reason, respstr, respdata)
        except (socket.timeout, socket.error) as e:
            LOG.error(_('ServerProxy: %(action)s failure, %(e)r'), locals())
            ret = 0, None, None, None
        conn.close()
        LOG.debug(_("ServerProxy: status=%(status)d, reason=%(reason)r, "
                    "ret=%(ret)s, data=%(data)r"), {'status': ret[0],
                                                    'reason': ret[1],
                                                    'ret': ret[2],
                                                    'data': ret[3]})
        return ret

    def server_failure(self, resp):
        """Define failure codes as required.
        Note: We assume 301-303 is a failure, and try the next server in
        the server pool.
        """
        return resp[0] in FAILURE_CODES

    def action_success(self, resp):
        """Defining success codes as required.
        Note: We assume any valid 2xx as being successful response.
        """
        return resp[0] in SUCCESS_CODES

    def get(self, resource, data='', headers=None):
        return self.rest_call('GET', resource, data, headers)

    def put(self, resource, data, headers=None):
        return self.rest_call('PUT', resource, data, headers)

    def post(self, resource, data, headers=None):
        return self.rest_call('POST', resource, data, headers)

    def delete(self, resource, data='', headers=None):
        return self.rest_call('DELETE', resource, data, headers)

    

class DbAccess(object):
    
    def get_port(self,port_id):
        ports = self.get_ports()
        for port in ports:
            if port.id == port_id:
                return port

    def get_ports(self):  
        session = db.get_session()
        with session.begin():    
            return session.query(models_v2.Port).all()
    
    def get_subnet(self,subnet_id):
        subnets = self.get_subnets()
        for subnet in subnets:
            if subnet.id == subnet_id:
                return subnet
            
    def get_subnet_network(self,network_id):
        subnets = self.get_subnets()
        for subnet in subnets:
            if subnet.network_id == network_id:
                return subnet  
                 
    def get_subnets(self):
        session = db.get_session()
        with session.begin():
            return session.query(models_v2.Subnet).all()
        
    def get_network(self,network_id):
        networks = self.get_networks()
        for network in networks:
            if network.id == network_id:
                return network
    
    def get_networks(self):
        session = db.get_session()
        with session.begin():
            return session.query(models_v2.Network).all()
    
    def get_vlan(self,network_id):
        session = db.get_session()
        with session.begin():
            vlans = session.query(models.NetworkSegment).all()
            for vlan in vlans:
                if vlan.network_id == network_id:
                    return vlan['segmentation_id'] 

class DellMechanismDriver(api.MechanismDriver):
    def initialize(self):
        self.server = Server()
        self.tenants = Set()
        self.db = DbAccess()
        self.provider_not_created = True
        self.hosts = Set()
        self.vms = Set()
        self.networks = Set()
        creds = self.get_nova_creds()
        self.nova = nvclient.Client(**creds)
        self.old_time = -1
        self.keystone = client.Client(username="admin", password="openflow", tenant_name="demo", auth_url="http://127.0.0.1:5000/v2.0")
        threading.Timer(20,self.reconcile_all).start()
    
    def post_tenant(self,tenant_id):
        if (tenant_id not in self.tenants):
            try:
                    resource = TENANT_URI % (tenant_id, provider_id)
                    data = {
                        "tenantId": tenant_id,
                        "providerId": provider_id,
                        "tenantName": self.keystone.tenants.get(tenant_id).__getattr__('name')
                        }
                    ret = self.server.post(resource, data)
                    if not self.server.action_success(ret):
                        raise RemoteRestError(ret[2])
                    self.tenants.add(tenant_id)
            except RemoteRestError as e:
                LOG.error(_("Dell Vulcan Tenant Creation error:Unable to create remote "
                            "tenant: %s"), e.message)
#  super(neutronRestProxyV2, self).delete_network(context,
#         new_net['id'])
                raise
        
        
    def post_provider(self):
        if (self.provider_not_created == True):
            try:
                    resource = PROVIDER_URI % (provider_id)
                    data = {
                        "providerId": provider_id,
                        "providerName": "openstack",
                        "providerDescription": "openstack provider"
                        }
                    ret = self.server.post(resource, data)
                    if not self.server.action_success(ret):
                        raise RemoteRestError(ret[2])
                    self.provider_not_created = False
            except RemoteRestError as e:
                    LOG.error(_("Dell Vulcan Provider Creation error:Unable to create remote "
                                "provider: %s"), e.message)
    #  super(neutronRestProxyV2, self).delete_network(context,
    #         new_net['id'])
                    raise 

    def create_network_postcommit(self,context):
        network = context.current
        vlanid = network['provider:segmentation_id']
        try:
                self.post_provider()
                self.post_tenant(network['tenant_id'])
                resource = NETWORK_URI % (network['id'], network['tenant_id'], provider_id)
                data = {
                    "networkId": network['id'], 
                    "tenantId": network['tenant_id'], 
                    "providerId": provider_id, 
                    "networkName": network['name'],
                    "networkVlanId": vlanid
                }
                ret = self.server.post(resource, data)
                if not self.server.action_success(ret):
                    raise RemoteRestError(ret[2])
                self.networks.add(network['id']+network['tenant_id'])
        except RemoteRestError as e:
                LOG.error(_("Dell Vulcan Network Creation error:Unable to create remote "
                            "network: %s"), e.message)
#  super(neutronRestProxyV2, self).delete_network(context,
#         new_net['id'])
                raise
            
    def create_subnet_postcommit(self,context):
        subnet = context.current
        network_id = subnet['network_id']+subnet['tenant_id']
        
        while network_id not in self.networks:
            time.sleep(5)
        network = context._plugin.get_network(context._plugin_context,subnet['network_id'])
        self.update_network(network,subnet)
        
    def update_network(self,network,subnet):
        resource = NETWORK_URI % (network['id'] , network['tenant_id'], provider_id) 
        try:
            vlan = network['provider:segmentation_id']
        except:
            vlan = self.db.get_vlan(network['id'])
        data = {
                    "networkId": network['id'], 
                    "tenantId": network['tenant_id'], 
                    "providerId": provider_id, 
                    "networkIP":subnet['cidr'][:-3],
                    "networkName": network['name'],
                    "networkVlanId":vlan,
                    "networkPrefix":subnet['cidr'][-2:]
                    
                     }
        self.put_no_exp(resource,data) 
            
    def update_network_postcommit(self,context):
        network = context.current
        subnets = (context._plugin_context.session.query(models_v2.Subnet).filter_by(network_id=network['id']).all())
        subnet = subnets[0]
        self.update_network(network,subnet)
           
    def post_non_vm_port(self, port):
        try:              
                self.post_provider()               
                ip = port['fixed_ips'][0]['ip_address']   
                if port['tenant_id'] != '': 
                    print port['tenant_id'] 
                    resource = PORT_URI % (port['mac_address'], port['tenant_id'], provider_id)               
                    self.post_tenant(port['tenant_id'])        
                    data = {
                                "endpointId": port['mac_address'],
                                "endpointAddress": port['mac_address'],
                                "tenantId": port['tenant_id'],
                                "providerId":provider_id,
                                "endpointIPAddress":[ip],
                                "endpointName":"",
                                "endpointType": "endpoint"
                    }
                else:                 
                    resource = PROVIDER_PORT_URI % (port['mac_address'],  provider_id)
                    data = {
                                "endpointId": port['mac_address'],
                                "endpointAddress": port['mac_address'],
                                "providerId":provider_id,
                                "endpointIPAddress":[ip],
                                "endpointName":"",
                                "endpointType": "endpoint"
                    }
                    
                ret = self.server.post(resource, data)
                if not self.server.action_success(ret):
                    raise RemoteRestError(ret[2])   
        except RemoteRestError as e:
                LOG.error(_("Dell Vulcan Endpoint Creation error:Unable to create remote "
                            "endpoint: %s"), e.message)
                
                    
    def delete_network_postcommit(self,context):
        network = context.current
        try:
                resource = NETWORK_URI % (network['id'], network['tenant_id'], provider_id)
                ret = self.server.delete(resource,"")
                if not self.server.action_success(ret):
                    raise RemoteRestError(ret[2])
        except RemoteRestError as e:
                LOG.error(_("Dell Vulcan Network Deletion error:Unable to delete remote "
                            "network: %s"), e.message)
          
    def create_port_postcommit(self,context):
        port = context.current
        self.post_port(port)
    
    def post_port(self,port):      
        try:            
            if port['device_owner'] != "compute:nova": 
                self.post_non_vm_port(port)
                return
            self.post_provider()
            ip = port['fixed_ips'][0]['ip_address']  
            self.post_tenant(port['tenant_id']) 
            resource = PORT_URI % (port['mac_address'], port['tenant_id'], provider_id)            
            vm = self.nova.servers.get(port['device_id'])
            name = vm.__getattr__('name')               
            data = {
            "endpointId": port['mac_address'],
            "endpointAddress": port['mac_address'],
            "tenantId": port['tenant_id'],
            "providerId":provider_id,
            "endpointIPAddress":[ip],
            "endpointName":name,
            "endpointType": "vm"
            }
            ret = self.server.post(resource, data)
            if not self.server.action_success(ret):
                raise RemoteRestError(ret[2])
            """
            Need to deploy the endpoint on network
            """
            net_id = port['network_id']+port['tenant_id']
            if net_id not in self.networks:
                resource = NETWORK_URI % (port['network_id'] , port['tenant_id'], provider_id)  
                network = self.db.get_network(port['network_id'])
                try:
                    vlan = network['provider:segmentation_id']
                except:
                    vlan = self.db.get_vlan(port['network_id'])
                try:
                    subnet = network['subnets'][0]
                except:
                    subnet = {'cidr':'0.0.0.0/24'}
                data = {
                        "networkId": port['network_id'], 
                        "tenantId": port['tenant_id'], 
                        "providerId": provider_id, 
                        "networkIP":subnet['cidr'][:-3],  
                        "networkName": network['name'],
                        "networkVlanId":vlan,
                        "networkPrefix":subnet['cidr'][-2:]                                               
                        }
                self.post_no_exp(resource,data)
                self.networks.add(net_id)
            resource = PORT_DEPLOY_URI % (port['network_id'], port['tenant_id'], provider_id, port['mac_address'], port['tenant_id'], provider_id)
            data = {
                    "networkId": port['network_id'],
                    "endpointId": port['mac_address'],
                    "endpointAddress": port['mac_address'],
                    "tenantId": port['tenant_id'],
                    "providerId":provider_id
                        }
            ret = self.server.post(resource, data)
            if not self.server.action_success(ret):
                raise RemoteRestError(ret[2])
            self.host_vm(port); 
        except RemoteRestError as e:
            LOG.error(_("Dell Vulcan Endpoint Creation error:Unable to create remote endpoint: %s"), e.message)
#  super(neutronRestProxyV2, self).delete_network(context,
#         new_net['id'])
            raise
        
    def delete_port_postcommit(self,context):
        port = context.current
        try:               
                #now delete from host if this is a vm endpoint
                if port['device_owner'] == "compute:nova":
                    vm = self.nova.servers.get(port['device_id'])
                    host = self.nova.hypervisors.search(vm.__getattr__('OS-EXT-SRV-ATTR:host'),False)[0]
                    endpoint =  port['mac_address']
                    resource = HOST_ENDPOINT_URI % (host.hypervisor_hostname.replace(".","-"),port['tenant_id'],provider_id,endpoint,port['tenant_id'],provider_id)
                    ret = self.server.delete(resource, "")
                    if not self.server.action_success(ret):
                        raise RemoteRestError(ret[2])
                #some ports don't belong to tenant  
                if port['tenant_id'] != '' :    
                    resource = PORT_URI % (port['mac_address'], port['tenant_id'], provider_id)
                else :
                    resource = PROVIDER_PORT_URI % (port['mac_address'], provider_id)
                ret = self.server.delete(resource, "")
                if not self.server.action_success(ret):
                    raise RemoteRestError(ret[2])
                    
        except RemoteRestError as e:
                LOG.error(_("Dell Vulcan Endpoint Deletion error:Unable to delete remote "
                            "endpoint: %s"), e.message)
                raise
    
    def host_vm(self,port): 
        if port['device_owner'] == "compute:nova":
            vm = self.nova.servers.get(port['device_id'])
            host = self.nova.hypervisors.search(vm.__getattr__('OS-EXT-SRV-ATTR:host'),False)[0]
            hostid = host.hypervisor_hostname+port['tenant_id']
            if hostid not in self.hosts:
                resource = HOST_URI % (host.hypervisor_hostname.replace(".","-"),port['tenant_id'],provider_id)
                data = {
                    "hostId":host.hypervisor_hostname.replace(".","-"),
                    "hostName":host.hypervisor_hostname.replace(".","-")
                        }
                self.post_no_exp(resource,data) 
                self.hosts.add(hostid)
            endpoint =  port['mac_address']                
            resource = HOST_ENDPOINT_URI % (host.hypervisor_hostname.replace(".","-"),port['tenant_id'],provider_id,endpoint,port['tenant_id'],provider_id)
            data = {
                "hostId":host.hypervisor_hostname.replace(".","-"),
                "hostName":host.hypervisor_hostname.replace(".","-")     
            }
            self.post_no_exp(resource,data)
         
    def reconcile(self):  
        self.hosts.clear()
        self.vms.clear()
        self.networks.clear()
        self.provider_not_created = True
        self.tenants.clear()
          
        #get all ports
        ports = self.db.get_ports()                           
        for port in ports:
            if (port['device_owner'] != "compute:nova"):
                self.post_non_vm_port(port)
            else:
                self.post_port(port)
        networks = self.db.get_networks()
        for network in networks:
            if ((network['id'] + network['tenant_id']) not in self.networks):
                subnet = self.db.get_subnet_network(network['id'])
                self.update_network(network, subnet)
                
    def reconcile_all(self):     
        heartbeat = loopingcall.LoopingCall(self.check_vulcan)
        try:
            heartbeat.start(interval=40,initial_delay =40)
        except:
            self.reconcile_all()
      
    def check_vulcan(self): 
        try:
            resource = CONTROLLER_TIME_URI          
            ret = self.server.get(resource)
            if not self.server.action_success(ret):
                raise RemoteRestError(ret[2])
            time = long(ret[3]) 
            temp = self.old_time
            self.old_time = time
            if time != temp :   
                LOG.error("need to reconcile")           
                self.reconcile()
        except RemoteRestError:      
                pass
         
    def post_no_exp(self,resource,data):
        try:
            ret = self.server.post(resource, data)
            if not self.server.action_success(ret):
                LOG.error(_("post error"),ret[2])
        except RemoteRestError as e:
                LOG.error(_("Dell Vulcan API error:"), e.message)
                
    def put_no_exp(self,resource,data):
        try:
            ret = self.server.put(resource, data)
            if not self.server.action_success(ret):
                LOG.error(_("post error"),ret[2])
        except RemoteRestError as e:
                LOG.error(_("Dell Vulcan API error:"), e.message)
                 
    def get_nova_creds(self):
        d = {}
        d['username'] = "admin"
        d['api_key'] = "openflow"
        d['auth_url'] = "http://127.0.0.1:5000/v2.0"
        d['project_id'] = "demo"
        return d   
    