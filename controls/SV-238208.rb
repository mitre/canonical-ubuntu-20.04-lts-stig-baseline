control 'SV-238208' do
  title 'The Ubuntu operating system must require users to reauthenticate for privilege escalation or when changing roles.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.'
  desc 'check', %q(Verify the "/etc/sudoers" file has no occurrences of "!authenticate" by running the following command:

$ sudo egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d/

If any occurrences of "!authenticate" return from the command, this is a finding.)
  desc 'fix', 'Remove any occurrence of "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-238208'
  tag rid: 'SV-238208r1101674_rule'
  tag stig_id: 'UBTU-20-010014'
  tag fix_id: 'F-41377r1101673_fix'
  tag cci: ['CCI-002038', 'CCI-004895', 'CCI-000366']
  tag nist: ['IA-11', 'SC-11 b', 'CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable within a container without sudo installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || command('sudo').exist?
  }

  describe sudoers(input('sudoers_config_files')) do
    its('settings.Defaults') { should_not include '!authenticate' }
  end
end
