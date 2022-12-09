control 'SV-238236' do
  title "The Ubuntu operating system must be configured so that the script which runs each 30 days or
less to check file integrity is the default one. "
  desc "Without verification of the security functions, security functions may not operate
correctly and the failure may go unnoticed. Security function is defined as the hardware,
software, and/or firmware of the information system responsible for enforcing the system
security policy and supporting the isolation of code and data on which the protection is
based. Security functionality includes, but is not limited to, establishing system
accounts, configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

Notifications
provided by information systems include, for example, electronic alerts to System
Administrators, messages to local computer consoles, and/or hardware indications, such as
lights.

This requirement applies to the Ubuntu operating system performing security
function verification/testing and/or systems and environments that require this
functionality. "
  desc 'check', "Verify that the Advanced Intrusion Detection Environment (AIDE) default script used to
check file integrity each 30 days or less is unchanged.

Download the original aide-common
package in the /tmp directory:

$ cd /tmp; apt download aide-common

Fetch the SHA1 of the
original script file:

$ dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO
./usr/share/aide/config/cron.daily/aide | sha1sum

32958374f18871e3f7dda27a58d721f471843e26  -

Compare with the SHA1 of the file in the
daily or monthly cron directory:

$ sha1sum /etc/cron.{daily,monthly}/aide
2&gt;/dev/null
32958374f18871e3f7dda27a58d721f471843e26  /etc/cron.daily/aide

If
there is no AIDE script file in the cron directories, or the SHA1 value of at least one file in the
daily or monthly cron directory does not match the SHA1 of the original, this is a finding. "
  desc 'fix', "The cron file for AIDE is fairly complex as it creates the report. This file is installed with
the \"aide-common\" package, and the default can be restored by copying it from the package:


Download the original package to the /tmp dir:

$ cd /tmp; apt download aide-common


Extract the aide script to its original place:

$ dpkg-deb --fsys-tarfile
/tmp/aide-common_*.deb | sudo tar -x ./usr/share/aide/config/cron.daily/aide -C /


Copy it to the cron.daily directory:

$  sudo cp -f
/usr/share/aide/config/cron.daily/aide /etc/cron.daily/aide "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000446-GPOS-00200 '
  tag gid: 'V-238236 '
  tag rid: 'SV-238236r853415_rule '
  tag stig_id: 'UBTU-20-010074 '
  tag fix_id: 'F-41405r653882_fix '
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
  tag 'host', 'container'

  describe('Verify that the Advanced Intrusion Detection Environment (AIDE) default script used to check file integrity each 30 days or less is unchanged.') do
    skip('manual test')
  end
end
