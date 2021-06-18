# Pacemaker log parser

This repository contains the program to analyze logs from Linux Pacemaker High Availability cluster for SAP solutions running in Google Cloud Platform.

It can parse pacemaker logs, system logs, hb_report from SUSE and sosreport from Redhat.

It generates an output file with critical Pacemaker events such as fencing, resource actions and errors such as failed resource operations.

This is not an officially supported Google product

## How to use

The program requires Python 3.6+ to run.

**Show help:**

./logpaser -h

**Option '-p' to parse up to two pacemaker logs**

./logparser -p node1_pacemaker.log node2_pacemaker.log 

**Option '-s' to parse up to two system logs.**

./logparser -s node1_system_log node2_system_log

**Option '-hb' to parse one hb_report file from SLES.**

./logparser -hb hb_report.tar.bz2

**Option '-sos' to parse up to two sosreport from RHEL.**

./logparser -sos sosreport1.tar.xz sosreport2.tar.xz

**NOTE: At least one of the above four options is requried and they can be combined.**

**Optional options:**

Option '-o' to specify output file name. By default, the output is written to logparser.out

Option '-b' to specify analysis begin time in format YYYY-MM-DD or YYYY-MM-DD-HH:MM

Option '-e' to specify analysis end time in format YYYY-MM-DD or YYYY-MM-DD-HH:MM

Examples:

-o output.txt

-o output.txt -b 2021-02-22

-o output.txt -b 2021-02-22 -e 2021-02-25

-o output.txt -e 2021-02-25-00:00

## Understand Pacemaker logs

Below logs are filterted, captured and ordered in chronological order by the log parser

1. Fencing action, reason, and result

Examples:

2021-03-26 03:10:38 node1 pengine: notice: LogNodeActions:    * Fence (reboot) node2 'peer is no longer part of the cluster'

2021-03-26 03:10:57 node1 stonith-ng: notice: remote_op_done:    Operation 'reboot' targeting node1 on node2 for crmd.2569@node1.9114cbcc: OK

2020-12-21 12:15:18 node2 stonith-ng:notice: remote_op_done:        Operation reboot of node1 by node2 for crmd.126900@node1.a3ccb74f: Timer expired

2. Pacemaker actions to move/start/stop/recover/promote/demote cluster resources

Examples:

2021-03-26 03:10:38 node1 pengine: notice: LogAction:     * Move       rsc_vip_int-primary     ( node2 -> node1 )

2021-03-26 03:10:38 node1 pengine: notice: LogAction:     * Move       rsc_ilb_hltchk          ( node2 -> node1 )

2021-03-26 03:10:38 node1 pengine: notice: LogAction:     * Stop       rsc_SAPHanaTopology_SID_HDB00:1     (                 node2 )   due to node availability

3. Failed resource operations

Examples:

2021-03-26 04:50:48 node1 crmd: info: process_lrm_event: Result of monitor operation for rsc_SAPHana_SID_HDB00 on node1: 7 (not running) | call=232 key=rsc_SAPHana_SID_HDB00_monitor_61000 confirmed=false cib-update=345

2020-07-23 13:11:44 node2 crmd: info: process_lrm_event:        Result of monitor operation for rsc_vip_gcp_ers on node2: 7 (not running)

4. Corosync communication error and failure, also membership changes

Examples:

2021-11-25 03:19:32 node1 corosync: [TOTEM ] A processor failed, forming new configuration.

2021-11-25 03:19:33 node1 corosync: [TOTEM ] Failed to receive the leave message. failed: 2

2021-11-25 03:19:33 node2 corosync[2445]: message repeated 214 times: [   [TOTEM ] Retransmit List: 31609]

2021-11-25 03:19:33 node1 corosync: [TOTEM ] A new membership (10.0.0.10:2668) was formed. Members left: 2

2021-11-25 03:20:14 node1 corosync: [TOTEM ] A new membership (10.0.0.10:2672) was formed. Members joined: 2


5. Cluster/Node/Resource maintenance/standby/manage mode change

Examples:

(cib_perform_op)         info: +  /cib/configuration/crm_config/cluster_property_set[@id='cib-bootstrap-options']/nvpair[@id='cib-bootstrap-options-maintenance-mode']:  @value=true

(cib_perform_op)         info: +  /cib/configuration/nodes/node[@id='2']/instance_attributes[@id='nodes-2']/nvpair[@id='nodes-2-standby']:  @value=on

6. Resource agent, fence agent warnings and errors

Examples:

2021-03-16 14:12:31 node1 SAPHana(rsc_SAPHana_SID_HDB01): ERROR: ACT: HANA SYNC STATUS IS NOT 'SOK' SO THIS HANA SITE COULD NOT BE PROMOTED

2021-01-11 02:21:03 node1 stonith-ng[7812]:   notice: Operation 'monitor' [86041] for device 'STONITH-node1' returned: -62 (Timer expired)

2021-01-15 07:15:05 node1 gcp:stonith: ERROR - gcloud command not found at /usr/bin/gcloud

2021-02-08 17:05:30 node1 SAPInstance(rsc_sap_SID_ASCS10): ERROR: SAP instance service msg_server is not running with status GRAY !

2021-03-16 13:26:10 node2 SAPHana(rsc_SAPHana_SID_HDB01): INFO: ACT site=node2, setting SFAIL for secondary (5) - srRc=10 lss=4

7. High CPU load or Pacemaker critical logs

Examples:

2021-02-11 10:49:43 node1 crmd:   notice: High CPU load detected: 205.089996

2021-02-11 10:49:43 node2 crmd:   crit: tengine_stonith_notify: We were allegedly just fenced by node1 for node1!

8. Reach migration threshold and force resource off

Examples:

check_migration_threshold:        Forcing rsc_name away from node1 after 1000000 failures (max=5000)

9. Location constraint added due to manual resource movement

Examples:

2021-02-11 10:49:43 node2 cib: info: cib_perform_op:    ++ /cib/configuration/constraints:  <rsc_location id="cli-ban-grp_sap_cs_sid-on-node1" rsc="grp_sap_cs_sid" role="Started" node="node1" score="-INFINITY"/>

2021-02-11 11:26:29 node2 stonith-ng: info: update_cib_stonith_devices_v2:  Updating device list from the cib: delete rsc_location[@id='cli-prefer-grp_sap_cs_sid']
