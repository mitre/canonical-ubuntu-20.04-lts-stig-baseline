control 'SV-238335' do
  title "Ubuntu operating systems handling data requiring \"data at rest\" protections must employ
cryptographic mechanisms to prevent unauthorized disclosure and modification of the
information at rest. "
  desc "Information at rest refers to the state of information when it is located on a secondary
storage device (e.g., disk drive and tape drive, when used for backups) within an operating
system.

This requirement addresses protection of user-generated data, as well as
operating system-specific configuration data. Organizations may choose to employ
different mechanisms to achieve confidentiality and integrity protections, as
appropriate, in accordance with the security category and/or classification of the
information. "
  desc 'check', "If there is a documented and approved reason for not having data-at-rest encryption, this
requirement is Not Applicable.

Verify the Ubuntu operating system prevents unauthorized
disclosure or modification of all information requiring at-rest protection by using disk
encryption.

Determine the partition layout for the system with the following command:


#sudo fdisk -l
(..)
Disk /dev/vda: 15 GiB, 16106127360 bytes, 31457280 sectors
Units:
sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size
(minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier:
83298450-B4E3-4B19-A9E4-7DF147A5FEFB

Device       Start      End  Sectors Size Type
/dev/vda1
2048     4095     2048   1M BIOS boot
/dev/vda2     4096  2101247  2097152   1G Linux filesystem
/dev/vda3
2101248 31455231 29353984  14G Linux filesystem
(...)

Verify the system partitions are
all encrypted with the following command:

# more /etc/crypttab

Every persistent disk
partition present must have an entry in the file.

If any partitions other than the boot
partition or pseudo file systems (such as /proc or /sys) are not listed, this is a finding. "
  desc 'fix', "To encrypt an entire partition, dedicate a partition for encryption in the partition layout.


Note: Encrypting a partition in an already-installed system is more difficult because it
will need to be resized and existing partitions changed. "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000185-GPOS-00079 '
  tag gid: 'V-238335 '
  tag rid: 'SV-238335r654180_rule '
  tag stig_id: 'UBTU-20-010414 '
  tag fix_id: 'F-41504r654179_fix '
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
  tag 'host', 'container'

  describe 'Not Applicable' do
    skip 'Encryption of data at rest is handled by the IaaS'
  end
end
