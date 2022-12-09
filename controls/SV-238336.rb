control 'SV-238336' do
  title "The Ubuntu operating system must deploy Endpoint Security for Linux Threat Prevention
(ENSLTP). "
  desc "Without the use of automated mechanisms to scan for security flaws on a continuous and/or
periodic basis, the operating system or other system components may remain vulnerable to the
exploits presented by undetected software flaws.

To support this requirement, the
operating system may have an integrated solution incorporating continuous scanning using
HBSS and periodic scanning using other tools, as specified in the requirement. "
  desc 'check', "The Ubuntu operating system is not compliant with this requirement; hence, it is a finding.
However, the severity level can be mitigated to a CAT III if the ENSLTP module is installed and
running.

Check that the \"mcafeetp\" package has been installed:

# dpkg -l | grep mcafeetp


If the \"mcafeetp\" package is not installed, this finding will remain as a CAT II.

Check that
the daemon is running:

# /opt/McAfee/ens/tp/init/mfetpd-control.sh status

If the
daemon is not running, this finding will remain as a CAT II. "
  desc 'fix', "The Ubuntu operating system is not compliant with this requirement; however, the severity
level can be mitigated to a CAT III if the ENSLTP module is installed and running.

Configure
the Ubuntu operating system to use ENSLTP.

Install the \"mcafeetp\" package via the ePO
server. "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000191-GPOS-00080 '
  tag gid: 'V-238336 '
  tag rid: 'SV-238336r858538_rule '
  tag stig_id: 'UBTU-20-010415 '
  tag fix_id: 'F-41505r858537_fix '
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
  tag 'host', 'container'

  describe package('mfetp') do
    it { should be_installed }
  end

  describe command('/opt/McAfee/ens/tp/init/mfetpd-control.sh status') do
    its('exit_status') { should cmp 0 }
  end
end
