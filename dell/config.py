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
]


cfg.CONF.register_opts(DELL_DRIVER_OPTS, "ml2_dell")
