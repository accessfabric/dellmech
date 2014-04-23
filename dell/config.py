from oslo.config import cfg

DELL_DRIVER_OPTS = [cfg.StrOpt('controller_ip', 
                default='', 
                help=_("openflow controller ip address")),
                    cfg.StrOpt('controller_port', 
                default='',
                help=_("openflow controller port")),
                    cfg.StrOpt('provider_id',
                default='',
                help=_("openstack provider id")),
                    cfg.StrOpt('username',
                default='',
                help=_("openflow controller rest api user name")),
                    cfg.StrOpt('password',
                default='',
                help=_("openflow controller rest api password")),
                    cfg.StrOpt('adminuser',
                default='admin',
                help=_("openstack admin user")),
                    cfg.StrOpt('adminpwd',
                default='',
                help=_("openstack admin password")),
                    cfg.StrOpt('authurl',
                default='',
                help=_("openstack auth url")),
                    cfg.StrOpt('projectname',
                default='',
                help=_("openstack project name")),
]


cfg.CONF.register_opts(DELL_DRIVER_OPTS, "ml2_dell")
