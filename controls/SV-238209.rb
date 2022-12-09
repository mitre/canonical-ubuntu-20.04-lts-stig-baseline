control 'SV-238209' do
  title "The Ubuntu operating system default filesystem permissions must be defined in such a way that
all authenticated users can read and modify only their own files. "
  desc "Setting the most restrictive default permissions ensures that when new accounts are created
they do not have unnecessary access. "
  desc 'check', "Verify the Ubuntu operating system defines default permissions for all authenticated users
in such a way that the user can read and modify only their own files.

Verify the Ubuntu
operating system defines default permissions for all authenticated users with the
following command:

$ grep -i \"umask\" /etc/login.defs

UMASK 077

If the \"UMASK\"
variable is set to \"000\", this is a finding with the severity raised to a CAT I.

If the value of
\"UMASK\" is not set to \"077\", is commented out, or is missing completely, this is a finding. "
  desc 'fix', "Configure the system to define the default permissions for all authenticated users in such a
way that the user can read and modify only their own files.

Edit the \"UMASK\" parameter in the
\"/etc/login.defs\" file to match the example below:

UMASK 077 "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000480-GPOS-00228 '
  tag gid: 'V-238209 '
  tag rid: 'SV-238209r653802_rule '
  tag stig_id: 'UBTU-20-010016 '
  tag fix_id: 'F-41378r653801_fix '
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host', 'container'

  describe login_defs do
    its('UMASK') { should eq '077' }
  end
end
