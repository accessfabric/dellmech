dellmech
========
The Dell openstack ml2 mechanism driver.


Intended user : Existing openstack user. 


Pre-requisites:

a. Use neutron ml2 plugin

b. Use vlan as type driver



Please take the following steps to enable Dell Mechanims Driver:

1. stop neutron service.

2. sudo apt-get -y update

   sudo apt-get -y install git
   
cd to folder of ml2/drivers

   git init
   
git pull https://github.com/accessfabric/dellmech.git
   

3. in /etc/neutron/plugins/ml2, add ml2_dell_conf.ini

4. in /etc/neutron/plugins/ml2/ml2_conf.ini, find the line mechanism_drivers, add dell to the end of it.

5. locate the file neutron/neutron.egg-info/entry_points.txt, in the [neutron.ml2.mechanism_drivers] section, 
    add the line:dell = neutron.plugins.ml2.drivers.dell.mech_dell:DellMechanismDriver
   

6. restart neutron service
