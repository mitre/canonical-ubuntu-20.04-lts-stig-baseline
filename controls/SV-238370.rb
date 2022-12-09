control 'SV-238370' do
  title "The Ubuntu operating system must be configured so that Advance Package Tool (APT) removes all
software components after updated versions have been installed. "
  desc "Previous versions of software components that are not removed from the information system
after updates have been installed may be exploited by adversaries. Some information
technology products may remove older versions of software automatically from the
information system. "
  desc 'check', "Verify is configured to remove all software components after updated versions have been
installed with the following command:

$ grep -i remove-unused
/etc/apt/apt.conf.d/50unattended-upgrades

Unattended-Upgrade::Remove-Unused-Dependencies \"true\";

Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";

If the
\"::Remove-Unused-Dependencies\" and \"::Remove-Unused-Kernel-Packages\" parameters are
not set to \"true\" or are missing or commented out, this is a finding. "
  desc 'fix', "Configure APT to remove all software components after updated versions have been installed.


Add or updated the following options to the
\"/etc/apt/apt.conf.d/50unattended-upgrades\" file:


Unattended-Upgrade::Remove-Unused-Dependencies \"true\";

Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\"; "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000437-GPOS-00194 '
  tag gid: 'V-238370 '
  tag rid: 'SV-238370r853447_rule '
  tag stig_id: 'UBTU-20-010449 '
  tag fix_id: 'F-41539r654284_fix '
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
  tag 'host', 'container'

  describe directory('/etc/apt/apt.conf.d') do
    it { should exist }
  end

  describe command('grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades').stdout.strip do
    it { should match(/^\s*([^\s]*::Remove-Unused-Dependencies)\s*\"true\"\s*;$/) }
    it { should match(/^\s*([^\s]*::Remove-Unused-Kernel-Packages)\s*\"true\"\s*;$/) }
  end
end
