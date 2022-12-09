control 'SV-238211' do
  title "The Ubuntu operating system must use strong authenticators in establishing nonlocal
maintenance and diagnostic sessions. "
  desc "Nonlocal maintenance and diagnostic activities are those activities conducted by
individuals communicating through a network, either an external network (e.g., the
internet) or an internal network. Local maintenance and diagnostic activities are those
activities carried out by individuals physically present at the information system or
information system component and not communicating across a network connection.
Typically, strong authentication requires authenticators that are resistant to replay
attacks and employ multifactor authentication. Strong authenticators include, for
example, PKI where certificates are stored on a token protected by a password, passphrase, or
biometric. "
  desc 'check', "Verify the Ubuntu operating system is configured to use strong authenticators in the
establishment of nonlocal maintenance and diagnostic maintenance.

Verify that \"UsePAM\"
is set to \"yes\" in \"/etc/ssh/sshd_config:

$ grep -r ^UsePAM
/etc/ssh/sshd_config*

UsePAM yes

If \"UsePAM\" is not set to \"yes\", this is a finding.
If
conflicting results are returned, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to use strong authentication when establishing
nonlocal maintenance and diagnostic sessions.

Add or modify the following line to
/etc/ssh/sshd_config:

UsePAM yes "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000125-GPOS-00065 '
  tag gid: 'V-238211 '
  tag rid: 'SV-238211r858519_rule '
  tag stig_id: 'UBTU-20-010035 '
  tag fix_id: 'F-41380r653807_fix '
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe sshd_config do
      its('UsePAM') { should cmp 'yes' }
    end
  end
end
