control 'SV-238367' do
  title "The Ubuntu operating system must configure the uncomplicated firewall to rate-limit
impacted network interfaces. "
  desc "Denial of service (DoS) is a condition when a resource is not available for legitimate users.
When this occurs, the organization either cannot accomplish its mission or must operate at
degraded capacity.

This requirement addresses the configuration of the operating system
to mitigate the impact of DoS attacks that have occurred or are ongoing on system
availability. For each system, known and potential DoS attacks must be identified and
solutions for each type implemented. A variety of technologies exist to limit or, in some
cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing
memory partitions). Employing increased capacity and bandwidth, combined with service
redundancy, may reduce the susceptibility to some DoS attacks. "
  desc 'check', "Verify an application firewall is configured to rate limit any connection to the system.


Check all the services listening to the ports with the following command:

$ sudo ss -l46ut


Netid               State                Recv-Q                Send-Q                               Local Address:Port                               Peer Address:Port               Process
tcp                 LISTEN               0                     128
[::]:ssh                                        [::]:*

For each entry, verify that the Uncomplicated Firewall is configured to
rate limit the service ports with the following command:

$ sudo ufw status

Status: active


To                         Action      From
--                         ------      ----
22/tcp                     LIMIT       Anywhere
22/tcp (v6)                LIMIT       Anywhere (v6)

If
any port with a state of \"LISTEN\" is not marked with the \"LIMIT\" action, this is a finding. "
  desc 'fix', "Configure the application firewall to protect against or limit the effects of DoS attacks by
ensuring the Ubuntu operating system is implementing rate-limiting measures on impacted
network interfaces.

Check all the services listening to the ports with the following
command:

$ sudo ss -l46ut

Netid               State                Recv-Q                Send-Q                               Local Address:Port                               Peer
Address:Port               Process
tcp                 LISTEN               0                     128                                           [::]:ssh                                        [::]:*

For each service with a port
listening to connections, run the following command, replacing \"[service]\" with the
service that needs to be rate limited.

$ sudo ufw limit [service]

Rate-limiting can also
be done on an interface. An example of adding a rate-limit on the eth0 interface follows:

$
sudo ufw limit in on eth0 "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000420-GPOS-00186 '
  tag gid: 'V-238367 '
  tag rid: 'SV-238367r853444_rule '
  tag stig_id: 'UBTU-20-010446 '
  tag fix_id: 'F-41536r654275_fix '
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
  tag 'host', 'container'

  describe 'Status listings for any allowed services, ports, or applications must be documented with the organization' do
    skip 'Status listings checks must be preformed manually'
  end
end
