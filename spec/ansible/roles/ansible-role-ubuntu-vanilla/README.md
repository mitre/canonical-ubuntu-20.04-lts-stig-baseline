ansible-role-ubuntu-vanilla
===========================

This role prepares a plain Ubuntu 20.04 host for baseline validation without applying STIG hardening. It keeps the target close to a vanilla image while installing the utility packages needed by the test harness.

Requirements
------------

Ansible must be able to connect to the target with privileges sufficient to update packages and install dependencies from the configured apt repositories.

Role Variables
--------------

This role does not currently define any tunable variables.

Dependencies
------------

None.

Example Playbook
----------------

    - hosts: servers
      become: true
      roles:
         - ansible-role-ubuntu-vanilla

License
-------

Apache-2.0

Author Information
------------------

See the repository maintainers.
