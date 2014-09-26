# Copyright 2013 OpenStack Foundation
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Dell ML2 Mechanism Driver for AFC controller.
"""

from oslo.config import cfg

DELL_DRIVER_OPTS = [
    cfg.StrOpt('controller_ip',
               help=_("openflow controller ip address")),
    cfg.StrOpt('controller_port',
               help=_("openflow controller port")),
    cfg.StrOpt('provider_id',
               help=_("openstack provider id")),
    cfg.StrOpt('username',
               help=_("openflow controller rest api user name")),
    cfg.StrOpt('password',
               help=_("openflow controller rest api password")),
    cfg.StrOpt('adminuser',
               help=_("openstack admin user")),
    cfg.StrOpt('adminpwd',
               help=_("openstack admin password")),
    cfg.StrOpt('authurl',
               help=_("openstack auth url")),
    cfg.StrOpt('projectname',
               help=_("openstack project name")),
]
cfg.CONF.register_opts(DELL_DRIVER_OPTS, "ml2_dell")
