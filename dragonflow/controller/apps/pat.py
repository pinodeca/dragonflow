# Copyright (c) 2015 OpenStack Foundation.
# All Rights Reserved.
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

from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_log import log
from ryu.lib.packet import ethernet, icmp, in_proto, ipv4, packet
from ryu.ofproto import ether

from dragonflow import conf as cfg
from dragonflow.common import utils as df_utils
from dragonflow.controller import df_base_app, port_locator
from dragonflow.controller.common import arp_responder, constants as const, \
    icmp_error_generator
from dragonflow.db.models import constants as model_constants, l2, l3

LOG = log.getLogger(__name__)

EGRESS = 'egress'

INGRESS = 'ingress'


class PATApp(df_base_app.DFlowApp):
    def __init__(self, *args, **kwargs):
        super(PATApp, self).__init__(*args, **kwargs)
        # PATApp is currently piggy-backing on the DNATApp, so it doesn't
        # create its own tables and therefore will not handle packet misses.
        # TODO(pino): handle ICMP errors separate from DNATApp.

    def _get_vm_gateway_mac(self, pat_entry):
        for router_port in pat_entry.lrouter.ports:
            if router_port.lswitch.id == pat_entry.lport.lswitch.id:
                return router_port.mac
        return None

    def _get_arp_responder(self, pat):
        # ARP responder is placed in L2. This is needed to avoid the multicast
        # flow for provider network in L2 table.
        # The packet is egressed to EGRESS_TABLE so it can reach the provider
        # network.
        return arp_responder.ArpResponder(
            app=self,
            network_id=pat.lport.lswitch.unique_key,
            interface_ip=pat.ip_address,
            interface_mac=pat.lport.mac,
            table_id=const.L2_LOOKUP_TABLE,
            priority=const.PRIORITY_HIGH,
            goto_table_id=const.EGRESS_TABLE,
            source_port_key=pat.lport.unique_key,
        )

    def _get_ingress_translate_actions(self, pat_entry):
        vm_gateway_mac = self._get_vm_gateway_mac(pat_entry)
        if vm_gateway_mac is None:
            vm_gateway_mac = pat_entry.pat.lport.mac

        return [
            self.parser.OFPActionDecNwTtl(),
            self.parser.OFPActionSetField(eth_src=vm_gateway_mac),
            self.parser.OFPActionSetField(eth_dst=pat_entry.lport.mac),
            self.parser.OFPActionSetField(ipv4_dst=pat_entry.fixed_ip_address),
            self.parser.OFPActionSetField(tcp_dst=pat_entry.fixed_l4_port),
            self.parser.OFPActionSetField(reg7=pat_entry.lport.unique_key),
            self.parser.OFPActionSetField(
                metadata=pat_entry.lport.lswitch.unique_key),
        ]

    def _get_pat_ingress_match(self, pat, **kwargs):
        return self.parser.OFPMatch(
            reg7=pat.lport.unique_key,
            **kwargs
        )

    def _get_pat_entry_ingress_match(self, pat_entry, **kwargs):
        return self.parser.OFPMatch(
            reg7=pat_entry.pat.lport.unique_key,
            eth_type=ether.ETH_TYPE_IP,
            ip_proto=n_const.PROTO_NUM_TCP,
            tcp_dst=pat_entry.pat_l4_port,
            **kwargs
        )

    def _get_pat_egress_match(self, pat_entry, **kwargs):
        return self.parser.OFPMatch(
            metadata=pat_entry.lport.lswitch.unique_key,
            reg6=pat_entry.lport.unique_key,
            reg5=pat_entry.lrouter.unique_key,
            eth_type=ether.ETH_TYPE_IP,
            ipv4_src=pat_entry.fixed_ip_address,
            ip_proto=n_const.PROTO_NUM_TCP,
            tcp_src=pat_entry.fixed_l4_port,
            **kwargs
        )

    def _get_egress_nat_actions(self, pat_entry):
        parser = self.parser

        return [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=pat_entry.pat.lport.mac),
            parser.OFPActionSetField(eth_dst=const.EMPTY_MAC),
            parser.OFPActionSetField(ipv4_src=pat_entry.pat.ip_address),
            parser.OFPActionSetField(tcp_src=pat_entry.pat_l4_port),
            parser.OFPActionSetField(
                metadata=pat_entry.pat.lport.lswitch.unique_key),
            parser.OFPActionSetField(reg6=pat_entry.pat.lport.unique_key)
        ]

    def _install_pat_ingress_flows(self, pat):
        self._get_arp_responder(pat).add()
        self.mod_flow(
            table_id=const.EGRESS_TABLE,
            priority=const.PRIORITY_HIGH,
            match=self._get_pat_ingress_match(pat),
            inst=[
                self.parser.OFPInstructionGotoTable(const.INGRESS_DNAT_TABLE),
            ],
        )

    def _uninstall_pat_ingress_flows(self, pat):
        self._get_arp_responder(pat).remove()
        self.mod_flow(
            command=self.ofproto.OFPFC_DELETE_STRICT,
            table_id=const.EGRESS_TABLE,
            priority=const.PRIORITY_HIGH,
            match=self._get_pat_ingress_match(pat),
        )

    def _install_pat_entry_ingress_flows(self, pat_entry):
        self.mod_flow(
            table_id=const.INGRESS_DNAT_TABLE,
            priority=const.PRIORITY_MEDIUM,
            match=self._get_pat_entry_ingress_match(pat_entry),
            actions=self._get_ingress_translate_actions(pat_entry) + [
                self.parser.NXActionResubmitTable(
                    table_id=const.L2_LOOKUP_TABLE),
            ],
        )

    def _uninstall_pat_entry_ingress_flows(self, pat_entry):
        self.mod_flow(
            command=self.ofproto.OFPFC_DELETE_STRICT,
            table_id=const.INGRESS_DNAT_TABLE,
            priority=const.PRIORITY_MEDIUM,
            match=self._get_pat_entry_ingress_match(pat_entry),
        )

    def _install_egress_flows(self, pat_entry):
        # Capture flow: relevant packets in L3 go to EGRESS_DNAT
        self.mod_flow(
            table_id=const.L3_LOOKUP_TABLE,
            priority=const.PRIORITY_MEDIUM_LOW,
            match=self._get_pat_egress_match(pat_entry),
            inst=[
                self.parser.OFPInstructionGotoTable(const.EGRESS_DNAT_TABLE)
            ],
        )
        self.mod_flow(
            table_id=const.EGRESS_DNAT_TABLE,
            priority=const.PRIORITY_MEDIUM,
            match=self._get_pat_egress_match(pat_entry),
            actions=self._get_egress_nat_actions(pat_entry) + [
                self.parser.NXActionResubmitTable(
                    table_id=const.L2_LOOKUP_TABLE,
                )
            ],
        )

    def _uninstall_egress_flows(self, pat_entry):
        self.mod_flow(
            command=self.ofproto.OFPFC_DELETE_STRICT,
            table_id=const.L3_LOOKUP_TABLE,
            priority=const.PRIORITY_MEDIUM_LOW,
            match=self._get_pat_egress_match(pat_entry),
        )
        self.mod_flow(
            command=self.ofproto.OFPFC_DELETE_STRICT,
            table_id=const.EGRESS_DNAT_TABLE,
            priority=const.PRIORITY_MEDIUM,
            match=self._get_pat_egress_match(pat_entry),
        )

    def _get_pats_by_lport(self, lport):
        return self.db_store.get_all(
            l3.PAT(lport=lport.id),
            index=l3.PAT.get_index('lport'),
        )

    def _get_pat_entries_by_pat(self, pat):
        return self.db_store.get_all(
            l3.PATEntry(pat=pat.id),
            index=l3.PATEntry.get_index('pat'),
        )

    def _get_pat_entries_by_lport(self, lport):
        return self.db_store.get_all(
            l3.PATEntry(lport=lport.id),
            index=l3.PATEntry.get_index('lport'),
        )

    @df_base_app.register_event(l2.LogicalPort, l2.EVENT_BIND_LOCAL)
    def _local_port_bound(self, lport):
        # If the port belongs to a PAT, install the ingress flows for the PAT
        # and all related PAT Entries.
        for pat in self._get_pats_by_lport(lport):
            self._install_pat_ingress_flows(pat)
            for pat_entry in self.get_pat_entries_by_pat(pat):
                self._install_pat_entry_ingress_flows(pat_entry)
        # If the port belongs to a PAT entry, install the egress flows.
        for pat_entry in self.get_pat_entries_by_lport(lport):
            self._install_egress_flows(pat_entry)

    @df_base_app.register_event(l2.LogicalPort, l2.EVENT_UNBIND_LOCAL)
    def _local_port_unbound(self, lport):
        for pat in self._get_pats_by_lport(lport):
            self._uninstall_pat_ingress_flows(pat)
            for pat_entry in self.get_pat_entries_by_pat(pat):
                self._uninstall_pat_entry_ingress_flows(pat_entry)
        for pat_entry in self.get_pat_entries_by_lport(lport):
            self._uninstall_egress_flows(pat_entry)

    @df_base_app.register_event(l3.PAT, model_constants.EVENT_CREATED)
    def _create_pat(self, pat):
        binding = l2.PortBinding(type=l2.BINDING_CHASSIS,
                                 chassis=pat.chassis)
        port_locator.set_port_binding(pat.lport, binding)
        if binding.is_local:
            pat.lport.emit_bind_local()
        else:
            pat.lport.emit_bind_remote()

    @df_base_app.register_event(l3.PAT, model_constants.EVENT_UPDATED)
    def _update_pat(self, pat, orig_pat):
        self._delete_pat(orig_pat)
        self._create_pat(pat)

    @df_base_app.register_event(l3.PAT, model_constants.EVENT_DELETED)
    def _delete_pat(self, pat):
        was_local = pat.lport.is_local
        port_locator.clear_port_binding(pat.lport)
        if was_local:
            pat.lport.emit_unbind_local()
        else:
            pat.lport.emit_unbind_remote()

    @df_base_app.register_event(l3.PATEntry, model_constants.EVENT_CREATED)
    def _create_pat_entry(self, pat_entry):
        # Only the controller, C1, local to the PAT's port installs ingress
        # flows. This avoids having all controllers install flows for all PAT
        # entries (at the cost of all forward packets going through C1).
        if pat_entry.pat.lport.is_local:
            self._install_pat_entry_ingress_flows(pat_entry)
        # Only the controller, C2, local to the PAT entry's port installs
        # egress flows - return packets go direct without traversing C1.
        if pat_entry.lport.is_local:
            self._install_egress_flows(pat_entry)

    @df_base_app.register_event(l3.PATEntry, model_constants.EVENT_UPDATED)
    def _update_pat_entry(self, pat_entry, orig_pat_entry):
        self._delete_pat_entry(orig_pat_entry)
        self._create_pat_entry(pat_entry)

    @df_base_app.register_event(l3.PATEntry, model_constants.EVENT_DELETED)
    def _delete_pat_entry(self, pat_entry):
        if pat_entry.pat.lport.is_local:
            self._uninstall_pat_entry_ingress_flows(pat_entry)
        if pat_entry.lport.is_local:
            self._uninstall_egress_flows(pat_entry)
