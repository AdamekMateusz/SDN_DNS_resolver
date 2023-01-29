# SDN_DNS_resolver
#ryu #python3 #dns

## About Project
The assumption of the project was to construct an application that, using the OpenFlow protocol, will enable decryption of dns addresses.
The project was made using mininet and ryu-manager. Ryu-manager is an implementation of the OpenFlow protocol in Python.
### How Looks our Network
![alt text](https://github.com/AdamekMateusz/SDN_DNS_resolver.git/blob/master/topology.png?raw=true)

### Example of work


#### Configure Enviroment 
Now we can must prepare our enviroment to run the procets we need:
+ Mininet
+ python2 and python3 version (You can check which version you have using whereis python) Urgent! Not all library is supported by python3.



```console
sudo apt-get install mininet
python -m pip install --user virtualenv 
python -m venv sdn
source sdn/bin/activate
pip install -r requirements.cfg
```

#### C