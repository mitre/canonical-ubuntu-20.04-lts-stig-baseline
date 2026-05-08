control 'SV-238212' do
  title 'The Ubuntu operating system must immediately terminate all network connections associated with SSH traffic after a period of inactivity.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific Ubuntu operating system functionality where the system owner, data owner, or organization requires additional assurance."
  desc 'check', %q(Verify all network connections associated with SSH traffic automatically terminate after a period of inactivity.

Verify the "ClientAliveCountMax" variable is set in the "/etc/ssh/sshd_config" file by performing the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*clientalivecountmax'

ClientAliveCountMax  1

If "ClientAliveCountMax" is not set, is not set to "1", or is commented out, this is a finding.

If conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the Ubuntu operating system to automatically terminate inactive SSH sessions after a period of inactivity.

Modify or append the following line in the "/etc/ssh/sshd_config" file, replacing "[Count]" with a value of 1:

ClientAliveCountMax 1

Restart the SSH daemon for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-41422r951465_chk'
  tag severity: 'medium'
  tag gid: 'V-238212'
  tag rid: 'SV-238212r1015158_rule'
  tag stig_id: 'UBTU-20-010036'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag fix_id: 'F-41381r653810_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  tag 'host'
  tag 'container-conditional'

  only_if('SSH is not installed on the system this requirement is Not Applicable', impact: 0.0) {
    service('sshd').enabled? || package('openssh-server').installed?
  }

  client_alive_count = input('sshd_client_alive_count_max')

  if %w[docker podman kubepods lxc].include?(virtualization.system) && !package('openssh-server').installed?
    impact 0.0
    describe 'skip' do
      skip 'SSH configuration does not apply inside containers. This control is Not Applicable.'
    end
  else
    describe 'SSH ClientAliveCountMax configuration' do
      it "should be set to #{client_alive_count}" do
        expect(sshd_active_config.ClientAliveCountMax).to(cmp(client_alive_count), "SSH ClientAliveCountMax is commented out or not set to the expected value (#{client_alive_count})")
      end
    end
  end
end
