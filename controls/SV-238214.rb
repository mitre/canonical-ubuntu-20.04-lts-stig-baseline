control 'SV-238214' do
  title "The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent
Banner before granting any local or remote connection to the system. "
  desc "Display of a standardized and approved use notification before granting access to the
publicly accessible operating system ensures privacy and security notification verbiage
used is consistent with applicable federal laws, Executive Orders, directives, policies,
regulations, standards, and guidance.

System use notifications are required only for
access via logon interfaces with human users and are not required when such human interfaces
do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the
following verbiage for operating systems that can accommodate banners of 1300 characters:


\"You are accessing a U.S. Government (USG) Information System (IS) that is provided for
USG-authorized use only.

By using this IS (which includes any device attached to this IS),
you consent to the following conditions:

-The USG routinely intercepts and monitors
communications on this IS for purposes including, but not limited to, penetration testing,
COMSEC monitoring, network operations and defense, personnel misconduct (PM), law
enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may
inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS
are not private, are subject to routine monitoring, interception, and search, and may be
disclosed or used for any USG-authorized purpose.

-This IS includes security measures
(e.g., authentication and access controls) to protect USG interests--not for your personal
benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent
to PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services by
attorneys, psychotherapists, or clergy, and their assistants. Such communications and
work product are private and confidential. See User Agreement for details.\"

Use the
following verbiage for operating systems that have severe limitations on the number of
characters that can be displayed in the banner:

\"I've read & consent to terms in IS user
agreem't.\"

 "
  desc 'check', "Verify the Ubuntu operating system displays the Standard Mandatory DoD Notice and Consent
Banner before granting access to the Ubuntu operating system via an SSH logon with the
following command:

$ grep -ir banner /etc/ssh/sshd_config*


/etc/ssh/sshd_config:Banner /etc/issue.net

The command will return the banner option
along with the name of the file that contains the SSH banner. If the line is commented out, this
is a finding.

If conflicting results are returned, this is a finding.

Verify the
specified banner file matches the Standard Mandatory DoD Notice and Consent Banner exactly:


$ cat /etc/issue.net

\"You are accessing a U.S. Government (USG) Information System (IS)
that is provided for USG-authorized use only.

By using this IS (which includes any device
attached to this IS), you consent to the following conditions:

-The USG routinely
intercepts and monitors communications on this IS for purposes including, but not limited
to, penetration testing, COMSEC monitoring, network operations and defense, personnel
misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.


-At any time, the USG may inspect and seize data stored on this IS.

-Communications using,
or data stored on, this IS are not private, are subject to routine monitoring, interception,
and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes
security measures (e.g., authentication and access controls) to protect USG
interests--not for your personal benefit or privacy.

-Notwithstanding the above, using
this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of
the content of privileged communications, or work product, related to personal
representation or services by attorneys, psychotherapists, or clergy, and their
assistants. Such communications and work product are private and confidential. See User
Agreement for details.\"

If the banner text does not match the Standard Mandatory DoD Notice
and Consent Banner exactly, this is a finding. "
  desc 'fix', "Set the parameter Banner in \"/etc/ssh/sshd_config\" to point to the \"/etc/issue.net\" file:


$ sudo sed -i '/^Banner/d' /etc/ssh/sshd_config
$ sudo sed -i '$aBanner /etc/issue.net'
/etc/ssh/sshd_config

Either create the file containing the banner or replace the text in
the file with the Standard Mandatory DoD Notice and Consent Banner. The DoD required text is:


\"You are accessing a U.S. Government (USG) Information System (IS) that is provided for
USG-authorized use only.

By using this IS (which includes any device attached to this IS),
you consent to the following conditions:

-The USG routinely intercepts and monitors
communications on this IS for purposes including, but not limited to, penetration testing,
COMSEC monitoring, network operations and defense, personnel misconduct (PM), law
enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may
inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS
are not private, are subject to routine monitoring, interception, and search, and may be
disclosed or used for any USG-authorized purpose.

-This IS includes security measures
(e.g., authentication and access controls) to protect USG interests--not for your personal
benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent
to PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services by
attorneys, psychotherapists, or clergy, and their assistants. Such communications and
work product are private and confidential. See User Agreement for details.\"

Restart the
SSH daemon for the changes to take effect and then signal the SSH server to reload the
configuration file:

$ sudo systemctl -s SIGHUP kill sshd "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000228-GPOS-00088 '
  tag satisfies: %w(SRG-OS-000228-GPOS-00088 SRG-OS-000023-GPOS-00006)
  tag gid: 'V-238214 '
  tag rid: 'SV-238214r858525_rule '
  tag stig_id: 'UBTU-20-010038 '
  tag fix_id: 'F-41383r653816_fix '
  tag cci: %w(CCI-000048 CCI-001384 CCI-001385 CCI-001386 CCI-001387 CCI-001388)
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 3']
  tag 'host', 'container'

  if !service('sshd').enabled? or !package('sshd-server').installed? or virtualization.system.eql?('docker')
    impact 0.0
    describe 'This control is Not Applicable' do
      if virtualization.system.eql?('docker')
        skip 'This control is Not Applicable in a container and/or the SSHD server is not enabled'
      else
        skip 'This control is Not Applicable since the SSHD server is not enabled and/or installed'
      end
    end
  else
    banner_text = input('banner_text')
    banner_files = [sshd_config.banner].flatten

    banner_files.each do |banner_file|
      if banner_file.nil?
        describe 'The SSHD Banner is not set' do
          subject { banner_file.nil? }
          it { should be false }
        end
      end
      if !banner_file.nil? && !banner_file.match(/none/i).nil?
        describe 'The SSHD Banner is disabled' do
          subject { banner_file.match(/none/i).nil? }
          it { should be true }
        end
      end
      if !banner_file.nil? && banner_file.match(/none/i).nil? && !file(banner_file).exist?
        describe 'The SSHD Banner is set, but, the file does not exist' do
          subject { file(banner_file).exist? }
          it { should be true }
        end
      end
      next unless !banner_file.nil? && banner_file.match(/none/i).nil? && file(banner_file).exist?

      describe 'The SSHD Banner is set to the standard banner and has the correct text' do
        clean_banner = banner_text.gsub(/[\r\n\s]/, '')
        subject { file(banner_file).content.gsub(/[\r\n\s]/, '') }
        it { should cmp clean_banner }
      end
    end
  end
end
