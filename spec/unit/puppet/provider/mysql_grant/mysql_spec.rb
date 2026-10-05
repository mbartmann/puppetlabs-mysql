# frozen_string_literal: true

require 'spec_helper'

describe Puppet::Type.type(:mysql_grant).provider(:mysql) do
  # The dynamic privileges MySQL 8.0.33 and later report for GRANT ALL ON *.*
  let(:dynamic_privileges) do
    ['APPLICATION_PASSWORD_ADMIN', 'AUDIT_ABORT_EXEMPT', 'AUDIT_ADMIN', 'AUTHENTICATION_POLICY_ADMIN', 'BACKUP_ADMIN', 'BINLOG_ADMIN', 'BINLOG_ENCRYPTION_ADMIN',
     'CLONE_ADMIN', 'CONNECTION_ADMIN', 'ENCRYPTION_KEY_ADMIN', 'FIREWALL_EXEMPT', 'FLUSH_OPTIMIZER_COSTS', 'FLUSH_STATUS', 'FLUSH_TABLES', 'FLUSH_USER_RESOURCES',
     'GROUP_REPLICATION_ADMIN', 'GROUP_REPLICATION_STREAM', 'INNODB_REDO_LOG_ARCHIVE', 'INNODB_REDO_LOG_ENABLE', 'PASSWORDLESS_USER_ADMIN', 'PERSIST_RO_VARIABLES_ADMIN',
     'REPLICATION_APPLIER', 'REPLICATION_SLAVE_ADMIN', 'RESOURCE_GROUP_ADMIN', 'RESOURCE_GROUP_USER', 'ROLE_ADMIN', 'SENSITIVE_VARIABLES_OBSERVER',
     'SERVICE_CONNECTION_ADMIN', 'SESSION_VARIABLES_ADMIN', 'SET_USER_ID', 'SHOW_ROUTINE', 'SYSTEM_USER', 'SYSTEM_VARIABLES_ADMIN', 'TABLE_ENCRYPTION_ADMIN',
     'TELEMETRY_LOG_ADMIN', 'XA_RECOVER_ADMIN']
  end

  def show_grants(dynamic)
    <<~SQL_OUTPUT
      GRANT ALL PRIVILEGES ON *.* TO `admin`@`%` WITH GRANT OPTION
      GRANT #{dynamic.join(',')} ON *.* TO `admin`@`%` WITH GRANT OPTION
    SQL_OUTPUT
  end

  def privileges_read_back(dynamic)
    allow(described_class).to receive(:users).and_return(['admin@%'])
    allow(described_class).to receive(:mysql_caller).with("SHOW GRANTS FOR 'admin'@'%';", 'regular').and_return(show_grants(dynamic))
    described_class.instances.find { |i| i.name == 'admin@%/*.*' }.privileges
  end

  before :each do
    allow(described_class).to receive(:mysqld_version_string).and_return('8.0.46')
  end

  describe 'self.instances' do
    it 'reads ALL ON *.* with the MySQL 8.0.33+ dynamic privileges back as ALL' do
      expect(privileges_read_back(dynamic_privileges)).to eq(['ALL'])
    end

    it 'does not collapse a set missing one of those dynamic privileges' do
      privileges = privileges_read_back(dynamic_privileges - ['TELEMETRY_LOG_ADMIN'])
      expect(privileges).to include('ALL', 'FIREWALL_EXEMPT')
      expect(privileges.size).to eq(36)
    end
  end
end
