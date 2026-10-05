# frozen_string_literal: true

require 'spec_helper'

describe Puppet::Type.type(:mysql_grant).provider(:mysql) do
  let(:static_privileges) do
    "Alter\tTables\tTo alter the table\nCreate view\tTables\tTo create new views\nUsage\tServer Admin\tNo privileges - allow connect only\n"
  end
  let(:mysql80_dynamic) do
    ['APPLICATION_PASSWORD_ADMIN', 'AUDIT_ABORT_EXEMPT', 'AUDIT_ADMIN', 'AUTHENTICATION_POLICY_ADMIN', 'BACKUP_ADMIN', 'BINLOG_ADMIN', 'BINLOG_ENCRYPTION_ADMIN',
     'CLONE_ADMIN', 'CONNECTION_ADMIN', 'ENCRYPTION_KEY_ADMIN', 'FIREWALL_EXEMPT', 'FLUSH_OPTIMIZER_COSTS', 'FLUSH_STATUS', 'FLUSH_TABLES', 'FLUSH_USER_RESOURCES',
     'GROUP_REPLICATION_ADMIN', 'GROUP_REPLICATION_STREAM', 'INNODB_REDO_LOG_ARCHIVE', 'INNODB_REDO_LOG_ENABLE', 'PASSWORDLESS_USER_ADMIN', 'PERSIST_RO_VARIABLES_ADMIN',
     'REPLICATION_APPLIER', 'REPLICATION_SLAVE_ADMIN', 'RESOURCE_GROUP_ADMIN', 'RESOURCE_GROUP_USER', 'ROLE_ADMIN', 'SENSITIVE_VARIABLES_OBSERVER',
     'SERVICE_CONNECTION_ADMIN', 'SESSION_VARIABLES_ADMIN', 'SET_USER_ID', 'SHOW_ROUTINE', 'SYSTEM_USER', 'SYSTEM_VARIABLES_ADMIN', 'TABLE_ENCRYPTION_ADMIN',
     'TELEMETRY_LOG_ADMIN', 'XA_RECOVER_ADMIN']
  end
  let(:mysql84_dynamic) do
    mysql80_dynamic + ['ALLOW_NONEXISTENT_DEFINER', 'FLUSH_PRIVILEGES', 'OPTIMIZE_LOCAL_TABLE', 'SET_ANY_DEFINER', 'TRANSACTION_GTID_TAG']
  end

  def privileges_read_back(held:, registered:, table: '*.*')
    grants = "GRANT ALL PRIVILEGES ON #{table} TO `admin`@`%` WITH GRANT OPTION\n"
    grants += "GRANT #{held.join(',')} ON *.* TO `admin`@`%` WITH GRANT OPTION\n" unless held.empty?
    allow(described_class).to receive(:users).and_return(['admin@%'])
    allow(described_class).to receive(:mysql_caller).with("SHOW GRANTS FOR 'admin'@'%';", 'regular').and_return(grants)
    allow(described_class).to receive(:mysql_caller).with('SHOW PRIVILEGES', 'regular')
                                                    .and_return(static_privileges + registered.map { |p| "#{p}\tServer Admin\t\n" }.join)
    described_class.instances.find { |i| i.name == "admin@%/#{table}" }.privileges
  end

  before :each do
    allow(described_class).to receive(:mysqld_version_string).and_return('8.0.46')
  end

  describe 'self.instances' do
    it 'reads ALL back as ALL when it carries every dynamic privilege the server registers' do
      expect(privileges_read_back(held: mysql80_dynamic, registered: mysql80_dynamic)).to eq(['ALL'])
    end

    it 'reads ALL back as ALL on a server that registers dynamic privileges no fixed list knows' do
      allow(described_class).to receive(:mysqld_version_string).and_return('8.4.6')
      expect(privileges_read_back(held: mysql84_dynamic, registered: mysql84_dynamic)).to eq(['ALL'])
    end

    it 'does not collapse ALL missing one registered dynamic privilege' do
      privileges = privileges_read_back(held: mysql80_dynamic - ['TELEMETRY_LOG_ADMIN'], registered: mysql80_dynamic)
      expect(privileges).to include('ALL', 'FIREWALL_EXEMPT')
      expect(privileges.size).to eq(36)
    end

    it 'does not collapse ALL missing dynamic privileges the server registered later' do
      allow(described_class).to receive(:mysqld_version_string).and_return('8.4.6')
      expect(privileges_read_back(held: mysql80_dynamic, registered: mysql84_dynamic).size).to eq(37)
    end

    it 'reads a database-level ALL back as ALL' do
      expect(privileges_read_back(held: [], registered: mysql80_dynamic, table: 'app.*')).to eq(['ALL'])
    end
  end
end
