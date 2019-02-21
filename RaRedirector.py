#!/usr/bin/env python
#daemon RaRedirector
#    exec /mnt/flash/RaRedirector
#    no shutdown

import eossdk
import sys
from jsonrpclib import Server
import syslog

REDIRECTCOMMUNITY="500:5"
REDIRECTACL="RA-REDIRECT"
ACLENTRY=10
REDIRECTPOLICY="RA-REDIRECT"
REDIRECTCLASS="RA-REDIRECT"
REDIRECTNHG="RA-REDIRECT"
INTERFACENAME="Port-Channel736"
NHGDSTPREFIX="192.18.2.1"
NHGSRCPREFIX="10.10.10.1"

"""The EOS SDK Redirector.
There is a need to do source-based routing on certain prefixes and tunnel the packets originating from those subnets 
using GRE to a speficied destination.

The Redirector is an EOS SDK agent that is usable on Arista devices supporting Policy Based Routing. 

The agent monitors all the routes in the FIB. It checks the prefix for a particular community-list and if a prefix/subnet 
matches the specified community-list, the prefix is added to an ACL. The ACL is referenced in a class-map/policy-map 
which performs the Policy Based Routing.
"""

class RaRedirector(eossdk.AgentHandler, eossdk.FibHandler, eossdk.AclHandler, eossdk.PolicyMapHandler):
    def __init__( self, agentMgr, fibMgr, aclMgr, policyMapMgr, classMapMgr, nexthopGroupMgr):
        eossdk.AgentHandler.__init__(self, agentMgr)
        eossdk.FibHandler.__init__(self, fibMgr)
        eossdk.AclHandler.__init__(self, aclMgr)
        eossdk.PolicyMapHandler.__init__(self, policyMapMgr)
        self.tracer = eossdk.Tracer("RaRedirector")
        self.agentMgr_ = agentMgr
        self.fibMgr_ = fibMgr
        self.aclMgr_ = aclMgr
        self.policyMapMgr_ = policyMapMgr
        self.classMapMgr_ = classMapMgr
        self.nexthopGroupMgr_ = nexthopGroupMgr
        self.tracer.trace0("Constructed")

    def on_initialized( self ):
        self.tracer.trace1("Initialized")
        self.agentMgr_.status_set("Status:", "Administratively Up")
        #Set up all our options.
        global REDIRECTCOMMUNITY
        if self.agentMgr_.agent_option("REDIRECTCOMMUNITY"):
          self.on_agent_option("REDIRECTCOMMUNITY", self.agentMgr_.agent_option("REDIRECTCOMMUNITY"))
        else:
          #global REDIRECTCOMMUNITY
          #We'll just use the default community specified by global variable
          self.agentMgr_.status_set("REDIRECTCOMMUNITY:", "%s" % REDIRECTCOMMUNITY)
        # initialize the ACL
        global REDIRECTACL
        self.aclKey = eossdk.AclKey(REDIRECTACL, eossdk.ACL_TYPE_IPV4)

    def on_agent_option (self, optionName, value):
        if optionName == "REDIRECTCOMMUNITY":
          if not value:
              self.tracer.trace3("REDIRECTCOMMUNITY Deleted")
              self.agentMgr_.status_set("REDIRECTCOMMUNITY:", REDIRECTCOMMUNITY)
          else:
              self.tracer.trace3("Adding REDIRECTCOMMUNITY %s" % value)
              self.agentMgr_.status_set("REDIRECTCOMMUNITY:", "%s" % value)

    def update_acl(self, prefix):
        global ACLENTRY
        # Configure V4 ACL
        syslog.syslog("inside Update ACL, ACLENTRY No: %s" % ACLENTRY)
        aclRule = eossdk.AclRuleIp()
        aclRule.ip_protocol_is(4)
        aclRule.action_is(eossdk.ACL_PERMIT)
        syslog.syslog("ACL Rule Created")
        srcPfx = eossdk.IpPrefix(prefix)
        addr = eossdk.IpAddrMask(srcPfx.network(),
                                 srcPfx.prefix_length())
        aclRule.source_addr_is(addr)

        dstPfx = eossdk.IpPrefix("0.0.0.0/0")
        addr = eossdk.IpAddrMask(dstPfx.network(),
                                dstPfx.prefix_length())
        aclRule.destination_addr_is(addr)

        self.aclMgr_.acl_rule_set(self.aclKey, ACLENTRY, aclRule)
        ACLENTRY += 10
        syslog.syslog("ACL Updated: %s prefix added" % prefix)

    @staticmethod
    def eapi_execute(cli):
        switch = Server( "unix:/var/run/command-api.sock" )
        return switch.runCmds(1, [ 'enable',
                                    '%s' % cli ])

    def community_list_check(self, route_detail):
        for key, value in route_detail[1]["vrfs"]["default"]["bgpRouteEntries"].iteritems():
                if self.agentMgr_.agent_option("REDIRECTCOMMUNITY"):
                    if self.agentMgr_.agent_option("REDIRECTCOMMUNITY") in \
                            value["bgpRoutePaths"][0]["routeDetail"]["communityList"]:
                        syslog.syslog("Received community matches the REDIRECTCOMMUNITY %s. "
                                      "Updating the ACL"
                                      % self.agentMgr_.agent_option("REDIRECTCOMMUNITY"))
                        return True
                    else:
                        syslog.syslog("Received community does not match the REDIRECTCOMMUNITY %s"
                                      % self.agentMgr_.agent_option("REDIRECTCOMMUNITY"))
                        return False
                else:
                    if REDIRECTCOMMUNITY in value["bgpRoutePaths"][0]["routeDetail"]["communityList"]:
                        syslog.syslog("Received community matches the REDIRECTCOMMUNITY %s"
                                      % REDIRECTCOMMUNITY)
                        return True
                    else:
                        syslog.syslog("Received community does not match the REDIRECTCOMMUNITY %s"
                                      % REDIRECTCOMMUNITY)
                        return False

    def on_route_set(self, route):
        self.tracer.trace0("Last added hardware route entry %s" % route.route_key().prefix().to_string() )
        syslog.syslog("Last Added Route %s" % route.route_key().prefix().to_string())
        cli = "show ip bgp %s"% route.route_key().prefix().to_string()
        route_detail = self.eapi_execute(cli)
        if self.community_list_check(route_detail):
            self.update_acl(route.route_key().prefix().to_string())
            self.aclMgr_.acl_commit()
            syslog.syslog("ACL Commited")
            #for acl_rule in self.aclMgr_.acl_rule_ip_iter(self.aclKey):
            #    syslog.syslog("%s"% (acl_rule[1].to_string(),))
            if self.aclMgr_.acl_exists(self.aclKey):
                syslog.syslog("ACL Key Created")
                # Now build the class map for that ACL and commit it
                self.classMapKey = eossdk.PolicyMapKey(REDIRECTCLASS, eossdk.POLICY_FEATURE_PBR)
                self.class_map = eossdk.ClassMap(self.classMapKey)
                self.classMapRule = eossdk.ClassMapRule(self.aclKey)
                self.class_map.rule_set(10, self.classMapRule)
                self.classMapMgr_.class_map_is(self.class_map)
                self.cm = self.classMapMgr_.class_map(self.classMapKey)
                syslog.syslog("Set class map %s with %d rules" % (REDIRECTCLASS, len(self.cm.rules())))

                # Build the nexthop group that will setup the GRE tunnel
                self.nhg = eossdk.NexthopGroup(REDIRECTNHG, eossdk.NEXTHOP_GROUP_GRE)
                self.nhgEntry1 = eossdk.NexthopGroupEntry(eossdk.IpAddr(NHGDSTPREFIX))
                self.nhg.nexthop_set(0, self.nhgEntry1)
                self.nhg.source_ip_is(eossdk.IpAddr(NHGSRCPREFIX))
                self.nexthopGroupMgr_.nexthop_group_set(self.nhg)

                # Add the policy map rule matching our class map and tunnel the traffic
                self.policyMapKey = eossdk.PolicyMapKey(REDIRECTPOLICY,eossdk.POLICY_FEATURE_PBR)
                self.policy_map = eossdk.PolicyMap(self.policyMapKey)
                self.policyMapRule = eossdk.PolicyMapRule(self.classMapKey)
                self.policyMapAction = eossdk.PolicyMapAction(eossdk.POLICY_ACTION_NEXTHOP_GROUP)
                self.policyMapAction.nexthop_group_name_is(REDIRECTNHG)
                self.policyMapRule.action_set(self.policyMapAction)
                self.policy_map.rule_set(1, self.policyMapRule)
                self.policyMapMgr_.policy_map_is(self.policy_map)
                self.policyMapMgr_.policy_map_apply(self.policyMapKey, eossdk.IntfId(INTERFACENAME), eossdk.ACL_IN, True)
                syslog.syslog("Finished applying policy")
            else:
                syslog.syslog("ACL Key Not Created")

    def on_route_del(self, route_key):
        self.tracer.trace0("Last removed hardware route entry %s" % route_key.prefix().to_string() )
        self.agentMgr_.status_set("Last Removed Route", route_key.prefix().to_string() )
        syslog.syslog("Last removed hardware route entry %s" % route_key.prefix().to_string() )


if __name__ == "__main__":
    sdk_  = eossdk.Sdk()
    _ = RaRedirector(sdk_.get_agent_mgr(), sdk_.get_fib_mgr(1), sdk_.get_acl_mgr(), sdk_.get_policy_map_mgr(), sdk_.get_class_map_mgr(), sdk_.get_nexthop_group_mgr())
    sdk_.main_loop(sys.argv)