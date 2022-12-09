control 'SV-238331' do
  title "The Ubuntu operating system must automatically remove or disable emergency accounts after
72 hours. "
  desc "Emergency accounts are different from infrequently used accounts (i.e., local logon
accounts used by the organization's System Administrator
s when network or normal
logon/access is not available). Infrequently used accounts are not subject to automatic
termination dates.  Emergency accounts are accounts created in response to crisis
situations, usually for use by maintenance personnel. The automatic expiration or
disabling time period may be extended as needed until the crisis is resolved; however, it must
not be extended indefinitely. A permanent account should be established for privileged
users who need long-term maintenance accounts. "
  desc 'check', "Verify the Ubuntu operating system expires emergency  accounts within 72 hours or less.

For
every emergency account, run the following command to obtain its account expiration
information:

$ sudo chage -l account_name | grep expires

Password expires                                        : Aug 07, 2019

Account expires                                           : Aug 07, 2019

Verify each of these accounts has an expiration date set
within 72 hours of account creation.

If any of these accounts do not expire within 72 hours of
that account's creation, this is a finding. "
  desc 'fix', "If an emergency account must be created, configure the system to terminate the account after a
72-hour time period with the following command to set an expiration date on it. Substitute
\"account_name\" with the account to be created.

$ sudo chage -E $(date -d \"+3 days\" +%F)
account_name "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000123-GPOS-00064 '
  tag gid: 'V-238331 '
  tag rid: 'SV-238331r654168_rule '
  tag stig_id: 'UBTU-20-010410 '
  tag fix_id: 'F-41500r654167_fix '
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
  tag 'host', 'container'

  describe 'Manual verification required' do
    skip 'Manually verify if emergency account must be created
      the system must terminate the account after a 72 hour time period.'
  end
end
