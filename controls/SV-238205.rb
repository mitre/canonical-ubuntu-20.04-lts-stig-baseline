control 'SV-238205' do
  title 'The Ubuntu operating system must uniquely identify interactive users. '
  desc "To assure accountability and prevent unauthenticated access, organizational users must be
identified and authenticated to prevent potential misuse and compromise of the system.


Organizational users include organizational employees or individuals the organization
deems to have equivalent status of employees (e.g., contractors). Organizational users
(and processes acting on behalf of users) must be uniquely identified and authenticated to
all accesses, except for the following:

1) Accesses explicitly identified and documented
by the organization. Organizations document specific user actions that can be performed on
the information system without identification or authentication; and

2) Accesses that
occur through authorized use of group authenticators without individual authentication.
Organizations may require unique identification of individuals in group accounts (e.g.,
shared privilege accounts) or for detailed accountability of individual activity.

 "
  desc 'check', "Verify the Ubuntu operating system contains no duplicate User IDs (UIDs) for interactive
users with the following command:

$ awk -F \":\" 'list[$3]++{print $1, $3}' /etc/passwd

If
output is produced and the accounts listed are interactive user accounts, this is a finding. "
  desc 'fix', "Edit the file \"/etc/passwd\" and provide each interactive user account that has a duplicate
UID with a unique UID. "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000104-GPOS-00051 '
  tag satisfies: %w(SRG-OS-000104-GPOS-00051 SRG-OS-000121-GPOS-00062)
  tag gid: 'V-238205 '
  tag rid: 'SV-238205r653790_rule '
  tag stig_id: 'UBTU-20-010010 '
  tag fix_id: 'F-41374r653789_fix '
  tag cci: %w(CCI-000764 CCI-000804)
  tag nist: %w(IA-2 IA-8)
  tag 'host', 'container'

  user_list = command("awk -F \":\" 'list[$3]++{print $1}' /etc/passwd").stdout.split("\n")
  findings = Set[]

  user_list.each do |user_name|
    findings = findings << user_name
  end
  describe 'Duplicate User IDs (UIDs) must not exist for interactive users' do
    subject { findings.to_a }
    it { should be_empty }
  end
end
