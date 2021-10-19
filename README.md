# pf9-inventory

To run this project, first install flask and then run app.py
This will launch a flask server (on port 5000)

Note:
You need to provide the fqdn, email and password of the DU whose APIs need to be called in provider.py

It exposes an api at /combined_hosts which gives combined host and node data (as required by UI)

The provider continuously polls resmgr and qbert for fresh data.
