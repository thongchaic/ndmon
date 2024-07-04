# ndmon
The coexistence of dual-stack IPv4 and IPv6 networks is increasingly utilized by networking devices. Monitoring and analyzing device discovery protocols has become important for local network security. In this hobby project, ndmon is a useful tool for capturing and analyzing ARP and ND protocols.



# Install python libraries 
 - python3 -m pip install --upgrade pip
 - pip install ifcfg
 - pip install Cython 
 - pip install python-libpcap 

# Install libraries from source 
 - python3 -m pip install --upgrade pip
 - pip install ifcfg
 - pip install Cython 
 - git clone https://github.com/caizhengxin/python-libpcap.git
 - cd python-libpcap
 - python3 setup.py install 
 
# Start 
sudo python3 main.py
