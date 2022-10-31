# encoding: UTF-8

control "SV-238198" do
  title "The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent 
Banner before granting local access to the system via a graphical user logon. "
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
  desc "check", "Verify the Ubuntu operating system displays the Standard Mandatory DoD Notice and Consent 
Banner before granting access to the operating system via a graphical user logon. 
 
Note: If 
the system does not have a graphical user interface installed, this requirement is Not 
Applicable. 
 
Verify the operating system displays the exact approved Standard Mandatory 
DoD Notice and Consent Banner text with the command: 
 
$ grep ^banner-message-text 
/etc/gdm3/greeter.dconf-defaults 
 
banner-message-text=\"You are accessing a U.S. 
Government \\(USG\\) Information System \\(IS\\) that is provided for USG-authorized use 
only.\\s+By using this IS \\(which includes any device attached to this IS\\), you consent to the 
following conditions:\\s+-The USG routinely intercepts and monitors communications on 
this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, 
network operations and defense, personnel misconduct \\(PM\\), law enforcement \\(LE\\), and 
counterintelligence \\(CI\\) investigations.\\s+-At any time, the USG may inspect and seize 
data stored on this IS.\\s+-Communications using, or data stored on, this IS are not private, 
are subject to routine monitoring, interception, and search, and may be disclosed or used for 
any USG-authorized purpose.\\s+-This IS includes security measures \\(e.g., 
authentication and access controls\\) to protect USG interests--not for your personal 
benefit or privacy.\\s+-Notwithstanding the above, using this IS does not constitute 
consent to PM, LE or CI investigative searching or monitoring of the content of privileged 
communications, or work product, related to personal representation or services by 
attorneys, psychotherapists, or clergy, and their assistants. Such communications and 
work product are private and confidential. See User Agreement for details.\" 
 
If the 
banner-message-text is missing, commented out, or does not match the Standard Mandatory DoD 
Notice and Consent Banner exactly, this is a finding. "
  desc "fix", "Edit the \"/etc/gdm3/greeter.dconf-defaults\" file. 
 
Set the \"banner-message-text\" line 
to contain the appropriate banner message text as shown below: 
 
banner-message-text='You 
are accessing a U.S. Government (USG) Information System (IS) that is provided for 
USG-authorized use only.\\n\\nBy using this IS (which includes any device attached to this 
IS), you consent to the following conditions:\\n\\n-The USG routinely intercepts and 
monitors communications on this IS for purposes including, but not limited to, penetration 
testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), 
law enforcement (LE), and counterintelligence (CI) investigations.\\n\\n-At any time, the 
USG may inspect and seize data stored on this IS.\\n\\n-Communications using, or data stored 
on, this IS are not private, are subject to routine monitoring, interception, and search, and 
may be disclosed or used for any USG-authorized purpose.\\n\\n-This IS includes security 
measures (e.g., authentication and access controls) to protect USG interests--not for your 
personal benefit or privacy.\\n\\n-Notwithstanding the above, using this IS does not 
constitute consent to PM, LE or CI investigative searching or monitoring of the content of 
privileged communications, or work product, related to personal representation or 
services by attorneys, psychotherapists, or clergy, and their assistants. Such 
communications and work product are private and confidential. See User Agreement for 
details.' 
 
Update the GDM with the new configuration: 
 
$ sudo dconf update 
$ sudo 
systemctl restart gdm3 "
  impact 0.5
  tag severity: "medium "
  tag gtitle: "SRG-OS-000023-GPOS-00006 "
  tag gid: "V-238198 "
  tag rid: "SV-238198r653769_rule "
  tag stig_id: "UBTU-20-010003 "
  tag fix_id: "F-41367r653768_fix "
  tag cci: ["CCI-000048"]
  tag nist: ["AC-8 a"]
end