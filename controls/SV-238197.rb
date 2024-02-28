control 'SV-238197' do
  title "The Ubuntu operating system must enable the graphical user logon banner to display the
Standard Mandatory DoD Notice and Consent Banner before granting local access to the system
via a graphical user logon. "
  desc "Display of a standardized and approved use notification before granting access to the Ubuntu
operating system ensures privacy and security notification verbiage used is consistent
with applicable federal laws, Executive Orders, directives, policies, regulations,
standards, and guidance.

System use notifications are required only for access via logon
interfaces with human users and are not required when such human interfaces do not exist.


The banner must be formatted in accordance with applicable DoD policy. Use the following
verbiage for operating systems that can accommodate banners of 1300 characters:

\"You are
accessing a U.S. Government (USG) Information System (IS) that is provided for
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
agreem't.\" "
  desc 'check', "Verify the Ubuntu operating system is configured to display the Standard Mandatory DoD
Notice and Consent Banner before granting access to the operating system via a graphical user
logon.

Note: If the system does not have a graphical user interface installed, this
requirement is Not Applicable.

Check that the operating banner message for the graphical
user logon is enabled with the following command:

$ grep ^banner-message-enable
/etc/gdm3/greeter.dconf-defaults

banner-message-enable=true

If the line is
commented out or set to \"false\", this is a finding. "
  desc 'fix', "Edit the \"/etc/gdm3/greeter.dconf-defaults\" file.

Look for the
\"banner-message-enable\" parameter under the \"[org/gnome/login-screen]\" section and
uncomment it (remove the leading \"#\" characters):

Note: The lines are all near the bottom of
the file but not adjacent to each other.

[org/gnome/login-screen]


banner-message-enable=true

Update the GDM with the new configuration:

$ sudo dconf
update
$ sudo systemctl restart gdm3 "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000023-GPOS-00006 '
  tag gid: 'V-238197 '
  tag rid: 'SV-238197r653766_rule '
  tag stig_id: 'UBTU-20-010002 '
  tag fix_id: 'F-41366r653765_fix '
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
  tag 'host', 'container'

  xorg_status = command('which Xorg').exit_status

  if xorg_status == 0
    describe 'banner-message-enable must be set to true' do
      subject { command('grep banner-message-enable /etc/gdm3/greeter.dconf-defaults').stdout.strip }
      it { should match(/banner-message-enable\s*=\s*true/) }
    end
  else
    describe command('which Xorg').exit_status do
      skip("GUI not installed.\nwhich Xorg exit_status: " + command('which Xorg').exit_status.to_s)
    end
  end
end
