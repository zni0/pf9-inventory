import threading
import time
import requests
import copy

fqdn = ''
resmgr_url = fqdn+'resmgr/'
qbert_url = fqdn+'qbert/'
keystone_url = fqdn+'keystone/'
pwd = ''
user = ''

def login(username=user, password=pwd, tenant = 'service'):
    """
    Login using username, password, tenant
    :param username: user name
    :param password: password for user
    :param tenant: tenant to login
    :return: Keystone login response json
    """
    data = {
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "domain": {
                            "id": "default"
                        },
                        "name": username,
                        "password": password
                    }
                }
            },
            "scope": {
                "project": {
                    "domain": {
                        "id": "default"
                    },
                    "name": tenant
                }
            }
        }
    }
    url = keystone_url + 'v3/auth/tokens'
    r = requests.post(url,json=data,verify=False)
    r.raise_for_status()
    return r

def get_login_token():
    login_resp = login()
    token_id = login_resp.headers['X-Subject-Token']
    return token_id

def call_remote_service(url, headers = {}):
    """
    Call GET on remote URL, handle errors
    :param str url: URL endpoint to be invoked
    :return: JSON representation of the response
    :rtype: dict
    """
    try:
        r = requests.get(url,headers=headers)
        if r.status_code != requests.codes.ok:
            print('GET call on %s failed with return code %d', url, r.status_code)
            raise Exception
        return r.json()
    except Exception as e:
        print('GET call on %s failed', url)
        raise e

class Provider:

    def __init__(self):
        self._token = get_login_token()
        self._project_id = []
        self._raw_hosts = []
        self._raw_nodes = {}
        self._combined_hosts = {}
        self.resmgr_url = 'http://localhost:8083'
        self.qbert_url = 'http://localhost:3000'
        self.keystone_url = 'http://localhost:8080'
        t = threading.Thread(target=self._update_info)
        t.daemon = True
        t.start()
    
    def _update_info(self):
        while True:
            try:
                self.fill_project_ids()
                print(self._project_id)
                for project_id in self._project_id:
                    self._raw_nodes[project_id] = self.get_raw_nodes(project_id)
                    print(self._raw_nodes[project_id])
                self._raw_hosts = self.get_raw_hosts()

                for project_id in self._project_id:
                    try:
                        self.combine_host_info(project_id)
                    except Exception as e:
                        print(e)
                

                time.sleep(60)
            except Exception as e:
                print('in exception!')
                print(e)
    
    def get_combined_hosts(self,project_id):
        return self._combined_hosts[project_id]

    
    def clean_all(self):
        self._token = get_login_token()
        self._project_id = []
        self._raw_hosts = []
        self._raw_nodes = {}
        self._combined_hosts = {}

    def fill_project_ids(self):
        headers = {'X-Auth-Token': self._token}
        url = keystone_url+'/v3/auth/projects' 
        resp = call_remote_service(url,headers)
        p_id = []
        for tennant in resp['projects']:
            p_id.append(tennant['id'])
        self._project_id = p_id

    def get_raw_nodes(self,project_id):
        headers = {'X-Auth-Token': self._token}
        url = qbert_url+'/v3/'+project_id+'/nodes' 
        return call_remote_service(url,headers)

    def get_raw_hosts(self):
        headers = {'X-Auth-Token': self._token}
        url = resmgr_url+'/v1'+'/hosts' 
        return call_remote_service(url,headers)

    def combine_host_info(self,project_id):

        Nodes = [] # host_list
        nodesSelector = []
        resMgrHosts =[]
        CombinedHosts = {}
        neutronComponents = {
            'pf9-neutron-base': True,
            'pf9-neutron-ovs-agent': True,
            'pf9-neutron-l3-agent': True,
            'pf9-neutron-dhcp-agent': True,
            'pf9-neutron-metadata-agent': True,
        }
        neutronComponentsLength = len(neutronComponents.keys())

        CloudStack = {
            'Both' : 'both',
            'Openstack' : 'openstack',
            'Kubernetes' : 'k8s',
            'Unknown' : 'unknown',
        }

        formattedRoleMapping = {
            'pf9-ostackhost-neutron': { 'name': 'Hypervisor', 'stack': CloudStack['Openstack'] },
            'pf9-ostackhost': { 'name': 'Hypervisor', 'stack': CloudStack['Openstack'] },
            'pf9-ostackhost-neutron-vmw': { 'name': 'VMware Cluster', 'stack': CloudStack['Openstack'] },
            'pf9-ostackhost-vmw': { 'name': 'VMware Cluster', 'stack': CloudStack['Openstack'] },
            'pf9-ceilometer': { 'name': 'Telemetry', 'stack': CloudStack['Openstack'] },
            'pf9-ceilometer-vmw': { 'name': 'Telemetry', 'stack': CloudStack['Openstack'] },
            'pf9-cindervolume-base': { 'name': 'Block Storage', 'stack': CloudStack['Openstack'] },
            'pf9-designate': { 'name': 'Designate', 'stack': CloudStack['Openstack'] },
            'pf9-glance-role': { 'name': 'Image Library', 'stack': CloudStack['Openstack'] },
            'pf9-glance-role-vmw': { 'name': 'VMware Glance', 'stack': CloudStack['Openstack'] },
            'pf9-kube': { 'name': 'Containervisor', 'stack': CloudStack['Kubernetes'] },
            'pf9-ostackhost-neutron-ironic': { 'name': 'Ironic', 'stack': CloudStack['Openstack'] },
            'pf9-contrail-forwarder': { 'name': 'Contrail Forwarder', 'stack': CloudStack['Openstack'] },
            'pf9-midonet-forwarder': { 'name': 'MidoNet Node', 'stack': CloudStack['Openstack'] },
        }
        def getIpPreview(ips):
            for ip in ips:
                if ip[:3] != '192':
                    return ip
                return ips[0]

        def getNetworkInterfaces(host):
            extensions = host['extensions']
            ifaceMap = extensions['interfaces']['data']['iface_info']
            pairedIfaces = []
            ifaceList = []
            for obj in ifaceMap.keys():
                pairedIfaces.append([obj,ifaceMap[obj]])
            for pair in pairedIfaces:
                ifaces = pair[1]['ifaces']
                for iface in ifaces:
                    temp = {}
                    temp['name'] = pair[0]
                    temp['mac'] = pair[1]['mac']
                    temp['ip'] = iface['addr']
                    temp['netmask'] = iface['netmask']
                    temp['label'] = pair[0] + ": "+iface['addr']
                    ifaceList.append(temp)
            # TODO return ifaceList.flat() // [[interface, ip], [interface2, ip2], ...]
            # TODO common -> selector -> 34
            return ifaceList

        def check_if_unauthorized(host):
            return (host['roles'].count('pf9-kube') == 0)
        
        for host in self._raw_hosts:
            try:
                if check_if_unauthorized(host):
                    temp_dict = {}
                    temp_dict['name'] = host['info']['hostname']
                    temp_dict['uuid'] = host['id']
                    temp_dict['inAuthorized'] = False
                    Nodes.append(temp_dict)
                
                temp_dict = {}
                try:
                    temp_dict['ipPreview'] = getIpPreview(host['extensions']['ip_address']['data'])
                except Exception as e:
                    temp_dict['ipPreview'] = []                
                host['networkInterfaces'] = getNetworkInterfaces(host)
                try:
                    temp_dict['ovsBridges'] =  host['extensions']['interfaces']['data']['ovs_bridges']
                except Exception as e:
                    temp_dict['ovsBridges'] = [] 
                
                temp_dict.update(host)
                resMgrHosts.append(temp_dict)
            except Exception as e:
                print(host)
        
        print('ok till here 1')
        for node in self._raw_nodes[project_id]:
            temp = node
            temp['inAuthorized'] = True
            Nodes.append(temp)
        print('ok till here 2')
        def annotateResmgrFields(host):
            resmgrRoles = []
            extensions = host['resmgr']['extensions']
            message = {'warn' : host['resmgr']['message']}
            try:
                resmgrRoles = host['resmgr']['roles']
            except Exception as e:
                resmgrRoles = []
            # TODO ask John about vCenterIP and warnings
            dict = {
                'id': host['resmgr']['id'],
                'roles': resmgrRoles,
                'roleStatus': host['resmgr']['role_status'],
                'roleData': {},
                'responding': host['resmgr']['info']['responding'],
                'hostname': host['resmgr']['info']['hostname'],
                'osInfo': host['resmgr']['info']['os_info'],
                'networks': [],
                # 'vCenterIP': extensions['hypervisor_details']['data']['vcenter_ip'],
                'supportRole': (resmgrRoles.count('pf9-support') != 0), 
                'networkInterfaces': extensions['interfaces']['data']['iface_ip'],
                'warnings': message.get('warn')
            } 
            host.update(dict)
            return host

        def annotateUiState(host):
            resmgr = {}
            uiState = ""
            lastResponse = ""
            if host.get('resmgr'):
                resmgr = host['resmgr']
            roles = host['roles'] 
            roleStatus = host['roleStatus']
            responding  = host['responding']
            warnings = host['warnings']
            host['roles'].count('pf9-kube') == 0
            if (len(roles) == 0 or (len(roles) == 1 and (roles.count('pf9-support') != 0)) ):
                uiState = 'unauthorized'
            
            if responding:
                if (['converging', 'retrying'].count(roleStatus) !=0 ):
                    uiState = 'pending'

                if (roleStatus == 'ok' and len(roles) > 0):
                    uiState = 'online'
                if (warnings and len(warnings) > 0):
                    uiState = 'drifted'

            if ((not uiState) and (not responding)):
                uiState = 'offline'
                lastResponseTime = None
                if resmgr.get('info') and resmgr['info'].get('last_response_time'):
                    lastResponseTime = resmgr['info']['last_response_time']
                    # TODO have not implimented lastResponse keept it as NULL
                    lastResponse = ""
            
            credentials = ''
            if resmgr.get('extensions') and resmgr['extensions'].get('hypervisor_details') and resmgr['extensions']['hypervisor_details'].get('data') and resmgr['extensions']['hypervisor_details']['data'].get('credentials'):
                credentials = resmgr['extensions']['hypervisor_details']['data']['credentials']
            if credentials == 'invalid':
                uiState = 'invalid'
            if roleStatus == 'failed':
                uiState = 'error'

            dict = {'uiState':uiState, 'lastResponse':lastResponse}

            host.update(dict)
            return host

        def getCloudStack(stackSet):
            if len(stackSet) == 2:
                return CloudStack["Both"]
            if len(stackSet) == 1:
                return next(iter(stackSet))
            return CloudStack['Unknown']

        def annotateCloudStack(host):

            roles = []
            if host.get('roles'):
                roles = host['roles']
            neutronRoles = set()
            normalRoles = set()
            cloudStack = set()

            for role in roles:
                if neutronComponents.get(role) and neutronComponents[role]:
                    neutronRoles.add(role)
                else:
                    role_map = {'name': role}
                    if formattedRoleMapping.get(role):
                        role_map = formattedRoleMapping[role]
                    name = role_map.get('name')
                    stack = role_map.get('stack')
                    if stack:
                        cloudStack.add(stack)
                    normalRoles.add(name)
            hasAllNetworkRoles = (len(neutronRoles) == neutronComponentsLength)
            if (hasAllNetworkRoles):
                normalRoles.add('Network Node')
                cloudStack.add(CloudStack.Openstack)
            dict = {'cloudStack': getCloudStack(cloudStack), 'localizedRoles': list(normalRoles)}
            host.update(dict)
            return host

        def calcResourceUtilization(host):
            
            extensions = host['resmgr']['extensions']
            usage = None
            if extensions.get('resource_usage') and extensions['resource_usage'].get('data'):
                usage = extensions['resource_usage']['data'] 
            if not usage:
                dict = {'usage' : None}
                host.update(dict)
                return host
            
            cpu = usage['cpu']
            memory = usage['memory']
            disk = usage['disk']

            K = 1000
            M = 1000 * K
            G = 1000 * M
            Ki = 1024
            Mi = 1024 * Ki
            Gi = 1024 * Mi

            stats = {
                'compute': {
                    'current': cpu['used'] / G,
                    'max': cpu['total'] / G,
                    'units': 'GHz',
                    'type': 'used',
                },
                'memory': {
                    'current': (memory['total'] - memory['available']) / Gi,
                    'max': memory['total'] / Gi,
                    'units': 'GB',
                    'type': 'used',
                },
                'disk': {
                    'current': disk['used'] / Gi,
                    'max': disk['total'] / Gi,
                    'units': 'GB',
                    'type': 'used',
                }
            }
            dict = {'usage': stats}
            host.update(dict)
            return host

        def combineHost(host):
            host = annotateResmgrFields(host)
            host = annotateUiState(host)
            host = annotateCloudStack(host)
            host = calcResourceUtilization(host)
            return host

        for item in resMgrHosts :
            host = {}
            host['resmgr'] = item
            combined_hosts = combineHost(host)
            host.update(combined_hosts)
            CombinedHosts[item['id']]  = host
        print('ok till here 3')
        for node in self._raw_nodes[project_id]:
            CombinedHosts[node['uuid']] = CombinedHosts[node['uuid']]
            CombinedHosts[node['uuid']]['qbert'] = copy.deepcopy(node)
        
        def calculateNodeUsages(dict):
            return {'dummy': 'data'}
        def getNetworkingStackFromIp(dict):
            return {'dummy': 'data'}

        for node in self._raw_nodes[project_id]:
            try:
                combined = CombinedHosts[node['uuid']]
                usage = calculateNodeUsages(node['uuid'])
                dict = node
                dict['status'] = 'disconnected'
                if combined['responding']:
                    dict['status'] = node['status']
                
                dict['combined'] = combined
                dict['logs'] = fqdn + '/qbert/v3/' + node['uuid']
                dict['usage'] = usage
                dict['roles'] = combined['roles']
                dict['operatingSystem'] = combined['resmgr']['info']['os_info'] # || combined['osInfo']
                # TODO combined['qbert']['primaryIp'] not present !!!
                # dict['primaryNetwork'] = combined['qbert']['primaryIP']
                # dict['networkStack'] = getNetworkingStackFromIp(combined['qbert']['primaryIp'])
                dict['cpuArchitecture'] = combined['resmgr']['info']['arch']
                dict['networkInterfaces'] = combined['networkInterfaces']
                dict['networkInterfaces'] = combined['resmgr']['message']
                nodesSelector.append(dict)
            except Exception as e:
                print('in here for' + node)
        self._combined_hosts[project_id] = nodesSelector
    
    def get_combined_info(self):
        return self._combined_hosts
