dellmech
========
The Dell openstack ml2 mechanism driver.


Intended user : Existing openstack user. 


Pre-requisites:

a. Use neutron ml2 plugin

b. Use vlan as type driver



Please take the following steps to enable Dell Mechanims Driver:

1. stop neutron service.

2. cd to folder of neutron/plugins/ml2/drivers

   check out the folder and files in /dell from github

3. create file ml2_conf_dell.ini under /etc/neutron/plugins/ml2/, refer to the sample file in github.

4. in /etc/neutron/plugins/ml2/ml2_conf.ini, find the line mechanism_drivers, add dell to it. Here is an example of how it     may look like : mechanism_drivers = openvswitch,dell

5. locate the file neutron/neutron.egg-info/entry_points.txt, in the [neutron.ml2.mechanism_drivers] section, 
    add the line:dell = neutron.plugins.ml2.drivers.dell.mech_dell:DellMechanismDriver
   

6. restart neutron service, add --config-file = /etc/neutron/plugins/ml2/ml2_conf_dell.ini to the command.
