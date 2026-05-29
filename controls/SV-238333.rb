control 'SV-238333' do
  title 'The Ubuntu operating system must be configured to use TCP syncookies.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', %q(Verify the Ubuntu operating system is configured to use TCP syncookies.

Check the value of TCP syncookies with the following command:

$ sysctl net.ipv4.tcp_syncookies
net.ipv4.tcp_syncookies = 1

If the value is not "1", this is a finding.

Check the saved value of TCP syncookies with the following command:

$ sudo grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -v '#'

If no output is returned, this is a finding.)
  desc 'fix', %q(Configure the Ubuntu operating system to use TCP syncookies by running the following command:

$ sudo sysctl -w net.ipv4.tcp_syncookies=1

If "1" is not the system's default value, add or update the following line in "/etc/sysctl.conf":

net.ipv4.tcp_syncookies = 1)
  impact 0.5
  tag check_id: 'C-41543r654172_chk'
  tag severity: 'medium'
  tag gid: 'V-238333'
  tag rid: 'SV-238333r958528_rule'
  tag stig_id: 'UBTU-20-010412'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-41502r654173_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
  tag 'host'
  tag 'container'

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should cmp 1 }
  end
end
