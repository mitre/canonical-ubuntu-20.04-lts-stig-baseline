control 'SV-238208' do
  title 'The Ubuntu operating system must require users to reauthenticate for privilege escalation
or when changing roles.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not
have authorization.

When operating systems provide the capability to escalate a
functional capability, it is critical the user reauthenticate.'
  desc 'check', %q(Verify the "/etc/sudoers" file has no occurrences of "!authenticate" by running the following command: 
 
$ sudo egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d/
 
If any occurrences of "!authenticate" return from the command, this is a finding.)
  desc 'fix', 'Remove any occurrence of "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157']
  tag gid: 'V-238208'
  tag rid: 'SV-238208r1101674_rule'
  tag stig_id: 'UBTU-20-010014'
  tag fix_id: 'F-41377r1101673_fix'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'
  tag 'container'

  describe command("egrep -r -i '(nopasswd|!authenticate)' /etc/sudoers.d/ /etc/sudoers") do
    its('stdout.strip') { should be_empty }
  end
end
