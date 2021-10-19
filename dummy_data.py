import json
import copy
import uuid

from flask import Flask, jsonify
app = Flask(__name__)

stringr = '''
{
    "cert_info": {
      "details": {
        "expiry_date": 1666063875.0, 
        "serial_number": 594555565509505668044295230891216345963735283379, 
        "start_date": 1634527845.0, 
        "status": "successful", 
        "timestamp": 1634614312.946901, 
        "version": "Version.v3"
      }, 
      "refresh_info": {
        "message": "", 
        "status": "not-refreshed", 
        "timestamp": ""
      }
    }, 
    "extensions": {
      "cloud_metadata": {
        "data": {
          "instanceId": "", 
          "publicHostname": ""
        }, 
        "status": "ok"
      }, 
      "cpu_stats": {
        "data": {
          "load_average": "0.52 0.71 0.71"
        }, 
        "status": "ok"
      }, 
      "interfaces": {
        "data": {
          "iface_info": {
            "ens3": {
              "ifaces": [
                {
                  "addr": "10.128.147.127", 
                  "broadcast": "10.128.147.255", 
                  "netmask": "255.255.254.0"
                }, 
                {
                  "addr": "fe80::f816:3eff:febf:ebf2%ens3", 
                  "netmask": "ffff:ffff:ffff:ffff::/64"
                }
              ], 
              "mac": "fa:16:3e:bf:eb:f2"
            }, 
            "tunl0": {
              "ifaces": [
                {
                  "addr": "10.20.2.64", 
                  "broadcast": "10.20.2.64", 
                  "netmask": "255.255.255.255"
                }
              ], 
              "mac": "00:00:00:00"
            }
          }, 
          "iface_ip": {
            "ens3": "10.128.147.127", 
            "tunl0": "10.20.2.64"
          }, 
          "ovs_bridges": []
        }, 
        "status": "ok"
      }, 
      "ip_address": {
        "data": [
          "10.20.2.64", 
          "10.128.147.127"
        ], 
        "status": "ok"
      }, 
      "kube_api_status": {
        "data": {
          "responding": true
        }, 
        "status": "ok"
      }, 
      "listened_ports": {
        "data": {
          "tcp": "H4sIAAAAAAAAA62W3UrEMBCF732KXgsuk7/m584LBWERtb7A0i0iyFa6xec3qN3upF5U5yQXKSnzcSaT5ORh6Me+euraj6vHqukO+zxs+3b3Vl3v90N3PFZzu+2H7vXlsPjTjLux+/68GNv3aZqmQWm/odxVMoGcO8XR1yyly4q37V3zfHO/hqdI2wDkudrrOQ6jL2L1GaS+SHFePgDPGKrB+ublA/C08QheRumwUdbn0WdoIJA+p4iQ+QbnoPUNSik5b4pjMATvvLiQfJ2J83Ul5jmTgcB8teZxgPqSht4vta4tkhcpQM9HjN4jeUrnDuQFhT2/3sS/n9/pRj/xUkrOnhvRT8vzJWotzxKpRdz/eaWTQ3iLhAX55oeBozJOoo87L0TfoiACXmTGhtGHre8vAiU87rwAXmmWIt7CesW8XA/0/vNlnJAXyzjRfmEvA7G+0srF+riTy3ncyeU87uRyHndeKS9Zu7Q34fnF3gfcydfzPgGJYgGc8A8AAA==", 
          "udp": "H4sIAAAAAAAAA63RzQ6CMAwA4LtPsbOJZOVnkN68ePKg8gTIOmNimAH0+R0gCgKGOAtJlzK+tNsu16VmB0rvqz2LKZMmbXWaXNhaypyKgr1jo3M6n7LBl7hMSmqWi5u8tmXeJnBDh5sn8DDwOh6vqxyXbDLGPe6AGznghyaHKCJLr/0PAHqbLfpzzesIH8HtDPyneV/mz97zPqDfnv359bTZnvj0EAdXUYepf6GmPUURR6SUCImUQmUWVa92nopAoNd4RyvPjDs4uyp+90a5Wd4DFp6K4RAEAAA="
        }, 
        "status": "ok"
      }, 
      "pf9_kube_status": {
        "data": {
          "all_status_checks": [
            "Generate certs / Send signing request to CA", 
            "Start Runtime", 
            "Start etcd", 
            "Network configuration", 
            "Configure and start auth web hook / pf9-bouncer", 
            "Miscellaneous scripts and checks", 
            "Configure and start kubelet", 
            "Configure and start kube-proxy", 
            "Wait for k8s services and network to be up", 
            "Apply dynamic kubelet configuration", 
            "Configure and start Keepalived"
          ], 
          "all_tasks": [
            "Generate certs / Send signing request to CA", 
            "Prepare configuration", 
            "Configure Runtime", 
            "Start Runtime", 
            "Configure etcd", 
            "Start etcd", 
            "Network configuration", 
            "Configure CNI plugin", 
            "Configure and start auth web hook / pf9-bouncer", 
            "Miscellaneous scripts and checks", 
            "Configure and start kubelet", 
            "Configure and start kube-proxy", 
            "Wait for k8s services and network to be up", 
            "Apply and validate node taints", 
            "Apply dynamic kubelet configuration", 
            "Uncordon node", 
            "Deploy app catalog", 
            "Configure and start Keepalived", 
            "Configure and start pf9-sentry", 
            "Configure and start pf9-addon-operator", 
            "Drain all pods (stop only operation)"
          ], 
          "completed_tasks": [
            "Generate certs / Send signing request to CA", 
            "Prepare configuration", 
            "Configure Runtime", 
            "Start Runtime", 
            "Configure etcd", 
            "Start etcd", 
            "Network configuration", 
            "Configure CNI plugin", 
            "Configure and start auth web hook / pf9-bouncer", 
            "Miscellaneous scripts and checks", 
            "Configure and start kubelet", 
            "Configure and start kube-proxy", 
            "Wait for k8s services and network to be up", 
            "Apply and validate node taints", 
            "Apply dynamic kubelet configuration", 
            "Uncordon node", 
            "Deploy app catalog", 
            "Configure and start Keepalived", 
            "Configure and start pf9-sentry", 
            "Configure and start pf9-addon-operator", 
            "Drain all pods (stop only operation)"
          ], 
          "current_status_check": "", 
          "current_task": "", 
          "last_failed_status_check": "", 
          "last_failed_status_time": 0, 
          "last_failed_task": "", 
          "pf9_cluster_id": "64f36f0c-9e60-4eee-bf1c-3a566b70ba5c", 
          "pf9_cluster_role": "master", 
          "pf9_kube_node_state": "ok", 
          "pf9_kube_service_state": "true", 
          "pf9_kube_start_attempt": 0, 
          "status_check_timestamp": 1634635140
        }, 
        "status": "ok"
      }, 
      "physical_nics": {
        "data": {
          "default": "ens3", 
          "ens3": "10.128.147.127", 
          "tunl0": "10.20.2.64"
        }, 
        "status": "ok"
      }, 
      "pod_info": {
        "data": {
          "error": "none", 
          "last_updated": "2021-10-19 09:12:04", 
          "total_count": 1
        }, 
        "status": "ok"
      }, 
      "resource_usage": {
        "data": {
          "cpu": {
            "percent": 12.0, 
            "total": 2599990000, 
            "used": 311998800.0
          }, 
          "disk": {
            "percent": 11.0, 
            "total": 62254768128, 
            "used": 6821564416
          }, 
          "memory": {
            "available": 2265452544, 
            "percent": 41.4, 
            "total": 3863085056
          }
        }, 
        "status": "ok"
      }, 
      "volumes_present": {
        "data": [], 
        "status": "ok"
      }
    }, 
    "hypervisor_info": {
      "hypervisor_type": "kvm"
    }, 
    "id": "05d81193-4b74-4b4a-8cc9-3ca68d49ab6c", 
    "info": {
      "arch": "x86_64", 
      "cpu_info": {
        "cpu_arch": "X86_64", 
        "cpu_capacity": {
          "per_core": "1.3 Ghz", 
          "per_socket": "1.3 Ghz", 
          "per_thread": "1.3 Ghz", 
          "total": "2.6000 GHz"
        }, 
        "cpu_cores": 2, 
        "cpu_features": [
          "aes", 
          "apic", 
          "arat", 
          "avx", 
          "clflush", 
          "cmov", 
          "constant_tsc", 
          "cpuid", 
          "cpuid_fault", 
          "cx16", 
          "cx8", 
          "de", 
          "ept", 
          "flexpriority", 
          "fpu", 
          "fxsr", 
          "hypervisor", 
          "ibpb", 
          "ibrs", 
          "lahf_lm", 
          "lm", 
          "mca", 
          "mce", 
          "mmx", 
          "msr", 
          "mtrr", 
          "nopl", 
          "nx", 
          "osxsave", 
          "pae", 
          "pat", 
          "pcid", 
          "pclmulqdq", 
          "pge", 
          "pni", 
          "popcnt", 
          "pse", 
          "pse36", 
          "pti", 
          "rdtscp", 
          "rep_good", 
          "sep", 
          "sse", 
          "sse2", 
          "sse4_1", 
          "sse4_2", 
          "ssse3", 
          "syscall", 
          "tpr_shadow", 
          "tsc", 
          "tsc_deadline_timer", 
          "tsc_known_freq", 
          "tscdeadline", 
          "vme", 
          "vmx", 
          "vnmi", 
          "vpid", 
          "x2apic", 
          "xsave", 
          "xsaveopt", 
          "xtopology"
        ], 
        "cpu_model": {
          "model_id": 42, 
          "model_name": "Intel Xeon E312xx (Sandy Bridge, IBRS update)"
        }, 
        "cpu_sockets": 2, 
        "cpu_threads": {
          "per_core": 1.0, 
          "total": 2
        }, 
        "cpu_vendor": "GenuineIntel", 
        "virtual/physical": "virtual (VMware)"
      }, 
      "hostname": "test-pf9-atharva-ranade-1721764-400-1", 
      "last_response_time": null, 
      "os_family": "Linux", 
      "os_info": "Ubuntu 20.04 focal", 
      "responding": true
    }, 
    "message": "", 
    "role_status": "ok", 
    "roles": [
      "pf9-kube"
    ]
}
'''
dictq = {
    "actualKubeRoleVersion": "1.21.3-pmk.2311", 
    "api_responding": 1, 
    "cloudInstanceId": "", 
    "cloudProviderType": "local", 
    "cloudProviderUuid": "4cb19c54-4de8-4a49-a920-012423517611", 
    "clusterKubeRoleVersion": "1.21.3-pmk.2311", 
    "clusterName": "PF9-multi-node-cluster", 
    "clusterUuid": "64f36f0c-9e60-4eee-bf1c-3a566b70ba5c", 
    "isMaster": 1, 
    "masterless": 0, 
    "name": "test-pf9-atharva-ranade-1721764-400-1", 
    "nodePoolName": "defaultPool", 
    "nodePoolUuid": "3f988295-40c2-4f32-8e0d-e55b1df979b4", 
    "primaryIp": "10.128.147.127", 
    "projectId": "a5b7f697d42f41f3a2367f90f5ff9215", 
    "startKube": 1, 
    "status": "ok", 
    "uuid": "05d81193-4b74-4b4a-8cc9-3ca68d49ab6c"
}

dictr = json.loads(stringr)

n = 50
uuidL = []
for i in range(0,n):
  uuidL.append(str(uuid.uuid4()))
project_id = 'abc'

@app.route("/qbert")
def index1():
  listq = []
  for i in range(n):
    temp = uuidL[i]
    for key in dictq:
      if key == "uuid":
        dictq[key] = temp
      
    temp_dictq = copy.deepcopy(dictq)
    listq.append(temp_dictq)
    dr = {project_id:listq}
  return jsonify(dr)

@app.route("/resmgr")
def index2():
  listr = []
  for i in range(n):
    temp = uuidL[i]
    for key in dictr:
      if key == "id":
          dictr[key] = temp
        
    temp_dictr = copy.deepcopy(dictr)
    listr.append(temp_dictr)
  return jsonify(listr)

if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0', port=5001)

