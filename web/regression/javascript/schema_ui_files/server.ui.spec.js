/////////////////////////////////////////////////////////////
//
// pgAdmin 4 - PostgreSQL Tools
//
// Copyright (C) 2013 - 2026, The pgAdmin Development Team
// This software is released under the PostgreSQL Licence
//
//////////////////////////////////////////////////////////////


import pgAdmin from 'sources/pgadmin';
import ServerSchema from '../../../pgadmin/browser/server_groups/servers/static/js/server.ui';
import {genericBeforeEach, getCreateView, getEditView, getPropertiesView} from '../genericFunctions';

describe('ServerSchema', ()=>{

  const createSchemaObject = () => new ServerSchema([{
    label: 'Servers', value: 1,
  }], 0, {
    user_id: 'jasmine',
  });
  let schemaObj = createSchemaObject();
  let getInitData = ()=>Promise.resolve({});

  beforeEach(()=>{
    genericBeforeEach();
    pgAdmin.Browser.utils.support_ssh_tunnel = true;
  });

  it('create', async ()=>{
    await getCreateView(createSchemaObject());
  });

  it('edit', async ()=>{
    await getEditView(createSchemaObject(), getInitData);
  });

  it('properties', async ()=>{
    await getPropertiesView(createSchemaObject(), getInitData);
  });

  describe('passthrough_oauth_identity field', ()=>{
    it('passthrough_oauth_identity field exists as a switch in the Advanced group', ()=>{
      let field = schemaObj.fields.find(f => f.id === 'passthrough_oauth_identity');
      expect(field).toBeDefined();
      expect(field.type).toBe('switch');
      expect(field.group).toContain('Advanced');
    });

    it('username field is disabled when passthrough is enabled', ()=>{
      let field = schemaObj.fields.find(f => f.id === 'username');
      expect(field).toBeDefined();
      expect(typeof field.disabled).toBe('function');
      expect(field.disabled({passthrough_oauth_identity: true})).toBe(true);
      expect(field.disabled({passthrough_oauth_identity: false})).toBe(false);
    });

    it('password field is disabled when passthrough is enabled (independent of kerberos_conn)', ()=>{
      let field = schemaObj.fields.find(f => f.id === 'password');
      expect(field).toBeDefined();
      expect(typeof field.disabled).toBe('function');
      // Passthrough alone disables it
      expect(field.disabled({passthrough_oauth_identity: true, kerberos_conn: false})).toBe(true);
      // Kerberos alone still disables it (existing behaviour preserved)
      expect(field.disabled({passthrough_oauth_identity: false, kerberos_conn: true})).toBe(true);
      // Neither: enabled
      expect(field.disabled({passthrough_oauth_identity: false, kerberos_conn: false})).toBe(false);
    });
  });

  it('validate', ()=>{
    let state = {};
    let setError = jest.fn();

    schemaObj.validate(state, setError);
    expect(setError).toHaveBeenCalledWith('gid', 'Server group must be specified.');

    state.gid = 1;
    schemaObj.validate(state, setError);
    expect(setError).toHaveBeenCalledWith('host', 'Either Host name or Service must be specified.');

    state.host = '127.0.0.1';
    schemaObj.validate(state, setError);
    expect(setError).toHaveBeenCalledWith('username', 'Username must be specified.');

    state.username = 'postgres';
    schemaObj.validate(state, setError);
    expect(setError).toHaveBeenCalledWith('port', 'Port must be specified.');

    state.port = 5432;
    state.use_ssh_tunnel = true;
    schemaObj.validate(state, setError);
    expect(setError).toHaveBeenCalledWith('tunnel_host', 'SSH Tunnel host must be specified.');

    state.service = 'pgservice';
    state.tunnel_host = 'localhost';
    schemaObj.validate(state, setError);
    expect(setError).toHaveBeenCalledWith('tunnel_port', 'SSH Tunnel port must be specified.');

    state.tunnel_port = 8080;
    schemaObj.validate(state, setError);
    expect(setError).toHaveBeenCalledWith('tunnel_username', 'SSH Tunnel username must be specified.');

    state.tunnel_username = 'jasmine';
    state.tunnel_authentication = true;
    schemaObj.validate(state, setError);
    expect(setError).toHaveBeenCalledWith('tunnel_identity_file', 'SSH Tunnel identity file must be specified.');

    state.tunnel_identity_file = '/file/path/xyz.pem';
    schemaObj.validate(state, setError);
    expect(setError).toHaveBeenCalledWith('tunnel_keep_alive', 'Keep alive must be specified. Specify 0 for no keep alive.');

    state.tunnel_keep_alive = 0;
    expect(schemaObj.validate(state, setError)).toBe(false);
  });
});
