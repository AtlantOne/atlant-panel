import tempfile
import io
import unittest
from unittest.mock import Mock, patch

from atlantctl import Manager, main, private_write
from pathlib import Path
from control.console import Console, saved_language
from control.i18n import LANGUAGES, message


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.api=Mock()
        self.api.request.side_effect=AssertionError('Certificate menu must not require the VPN')
        self.manager=Manager({'state_dir':self.temp.name},api=self.api)
        self.manager.certificates.validator=Mock()

    def console(self,values,lang='ru'):
        answers=iter(values);output=[]
        def read(prompt):
            output.append(prompt)
            return next(answers)
        return Console(self.manager,lang,read,output.append),output

    def test_menu_creates_domain_certificate_without_json_input(self):
        for lang in LANGUAGES:
            identifier='panel-'+lang
            ui,output=self.console(['2','2','panel-'+lang+'.example.invalid','yes','yes','0','0'],lang)
            ui.run()
            self.assertIn('panel-'+lang+'.example.invalid',[job['tls']['host'] for job in self.manager.certificates.read()['jobs']])
            self.assertIn(message('certificates',lang),'\n'.join(output))
        self.api.request.assert_not_called()

    def test_cancelled_terms_or_mutation_do_not_write(self):
        for answers in [['example.invalid','no'],['example.invalid','yes','no']]:
            ui,_=self.console(answers)
            ui.create_certificate('acme-domain')
            self.assertFalse(self.manager.certificates.path.exists())

    def test_domain_creation_asks_no_job_id_email_or_staging(self):
        for lang in LANGUAGES:
            ui,output=self.console(['simple-'+lang+'.example.invalid','yes','yes'],lang)
            ui.create_certificate('acme-domain')
            prompts='\n'.join(output)
            for key in ('certificate_job_id','email','staging'):
                self.assertNotIn(message(key,lang)+':',prompts)
            job=self.manager.certificates.read()['jobs'][-1]
            self.assertFalse(job['tls']['staging'])
            self.assertEqual('',job['tls']['email'])

    def test_ip_creation_asks_only_port_and_commits_listener_with_job(self):
        self.manager.certificate_defaults=Mock(return_value={'ip':'8.8.8.8'})
        ui,output=self.console(['18081','yes','yes'])
        ui.create_certificate('acme-ip')
        current=self.manager.certificates.read()
        self.assertEqual('127.0.0.1:18081',current['challenge_listen'])
        self.assertEqual('8.8.8.8',current['jobs'][0]['tls']['host'])
        self.assertEqual(0,len(list((self.manager.certificates.state/'backups').glob('cert-config-*.json'))))
        self.api.request.assert_not_called()

    def test_invalid_ip_port_does_not_write_certificate_or_listener(self):
        self.manager.certificate_defaults=Mock(return_value={'ip':'8.8.8.8'})
        for value in ('0','65536','invalid'):
            ui,_=self.console([value])
            with self.assertRaises(ValueError):ui.create_certificate('acme-ip')
        self.assertFalse(self.manager.certificates.path.exists())

    def test_certificate_and_listener_reject_unsafe_remote_bind_atomically(self):
        from atlantctl import AdminError
        body={'mode':'acme-ip','host':'8.8.8.8','email':'','accept_terms':True,'staging':False,'challenge_listen':'0.0.0.0:18081'}
        import json
        with self.assertRaises(AdminError):self.manager.prepare('certjobcreate atomic '+json.dumps(body))
        self.assertFalse(self.manager.certificates.path.exists())

    def test_missing_ip_does_not_guess_or_ask_for_an_ip(self):
        from atlantctl import AdminError
        self.manager.certificate_defaults=Mock(return_value={})
        ui,_=self.console([])
        with self.assertRaises(AdminError):ui.create_certificate('acme-ip')
        self.assertFalse(self.manager.certificates.path.exists())

    def test_certificate_selection_is_by_number_not_internal_id(self):
        ui,_=self.console(['example.invalid','yes','yes'])
        ui.create_certificate('acme-domain')
        ui,output=self.console(['1'])
        job,revision=ui.selected_certificate()
        self.assertEqual('example.invalid',job['tls']['host'])
        self.assertNotIn(message('certificate_job_id','ru')+':','\n'.join(output))

    def test_certificate_menu_has_only_five_actions_and_never_merges_identities(self):
        for lang in LANGUAGES:
            ui,output=self.console(['0'],lang)
            ui.certificates()
            text='\n'.join(output)
            actions=[line for line in output if line.startswith('  ') and '. ' in line]
            self.assertEqual(6,len(actions))  # Five actions and Back.
            for key in ('certificate_shared','certificate_backups','certificate_service'):
                self.assertNotIn(message(key,lang),text)
            self.assertFalse(hasattr(ui,'shared_certificate'))
        self.api.request.assert_not_called()

    def test_certificate_status_preserves_different_hostnames_and_hides_raw_config(self):
        ui,output=self.console([])
        ui.run_command=Mock(side_effect=[
            {'settings':{'origin':'https://panel.example.invalid:9099','tls':{'mode':'manual','key_file':'/private/key.pem'}}},
            {'public_url':'https://8.8.8.8','tls':{'mode':'acme-ip','cache_dir':'/private/cache'}},
            {'jobs':[]}])
        ui.certificate_status()
        self.assertEqual(['panelsettings','tls','certjobs'],[call.args[0] for call in ui.run_command.call_args_list])
        text='\n'.join(output)
        self.assertIn('panel.example.invalid',text)
        self.assertIn('8.8.8.8',text)
        self.assertNotIn('/private/',text)

    def test_invalid_menu_selection_stays_in_menu(self):
        ui,output=self.console(['999','-1','x','0'])
        ui.run()
        self.assertEqual(3,output.count(message('invalid','ru')))

    def test_root_menu_has_no_vpn_management_and_logs_wait_for_selection(self):
        for lang in LANGUAGES:
            ui,output=self.console(['3','0','0'],lang)
            ui.run()
            text='\n'.join(output)
            for key in ('show_logs','change_log_level','show_log_path'):
                self.assertIn(message(key,lang),text)
            for key in ('inbounds','subscriptions','nodes','core_settings','users'):
                self.assertNotIn('. '+message(key,lang)+'\n',text)
        self.api.request.assert_not_called()

    def test_logs_view_only_runs_after_explicit_selection(self):
        ui,_=self.console(['1','0'])
        ui.run_command=Mock(return_value={'logs':['test']})
        ui.logs_menu()
        ui.run_command.assert_called_once_with('logs 50')

    def test_log_level_save_never_restarts_without_explicit_confirmation(self):
        for lang in LANGUAGES:
            ui,_=self.console(['2',''],lang)
            ui.run_command=Mock(side_effect=[{'verified':True,'log_level':'error','overridden_fields':[]},{'status':'ok'}])
            with patch.object(self.manager,'execute') as execute:
                ui.change_log_level()
            execute.assert_not_called()
            self.assertEqual('configsave {"log_level": "info"}',ui.run_command.call_args_list[1].args[0])

    def test_log_level_override_blocks_edit_without_mutation(self):
        ui,output=self.console([])
        ui.run_command=Mock(return_value={'verified':True,'overridden_fields':['log_level']})
        ui.change_log_level()
        self.assertEqual(1,ui.run_command.call_count)
        self.assertIn(message('cli_log_level_unavailable','ru'),output)

    def test_log_path_does_not_read_log_entries(self):
        ui,output=self.console([])
        ui.run_command=Mock()
        ui.show_log_path()
        ui.run_command.assert_not_called()
        self.assertTrue(any('journalctl -u atlant_vpn.service' in line for line in output))

    def test_main_menu_shows_full_link_without_separate_command(self):
        ui,output=self.console(['0'])
        ui.run()
        from control.access import entry_path
        expected=self.manager.panel_settings.effective()['origin']+entry_path(self.temp.name)
        self.assertTrue(any(expected in line for line in output))
        self.assertIn(message('panel_settings','ru'),'\n'.join(output))
        self.api.request.assert_not_called()

    def test_quick_port_editor_keeps_the_private_path_and_updates_origin(self):
        from control.access import entry_path
        prefix=entry_path(self.temp.name)
        for lang,port in [('ru',9443),('en',9444),('zh',9445)]:
            ui,output=self.console([str(port),'yes'],lang)
            ui.panel_port()
            settings=self.manager.panel_settings.effective()
            self.assertEqual(port,settings['port'])
            self.assertEqual('http://127.0.0.1:'+str(port),settings['origin'])
            self.assertEqual(prefix,entry_path(self.temp.name))
        self.api.request.assert_not_called()

    def test_panel_apply_restarts_only_the_panel_with_confirmation(self):
        ui,output=self.console(['yes'])
        with patch('subprocess.run',return_value=Mock(returncode=0)) as run:
            ui.restart_panel()
        self.assertEqual(2,run.call_count)
        self.assertEqual(['systemctl','restart','atlant-control.service'],run.call_args_list[0].args[0])
        self.assertEqual(['systemctl','is-active','--quiet','atlant-control.service'],run.call_args_list[1].args[0])
        ui,_=self.console(['no'])
        with patch('subprocess.run') as run:ui.restart_panel()
        run.assert_not_called()

    def test_remote_inbound_cli_uses_confirmed_scoped_commands_in_all_languages(self):
        remote='a'*32
        for lang in LANGUAGES:
            ui,output=self.console(['yes'],lang)
            self.manager.peers.admin=Mock(return_value={'ok':True,'result':{'applied':True}})
            ui.inbound_write('inboundapply 1',remote)
            self.manager.peers.admin.assert_called_once_with(remote,'inboundapply 1')
            expected=message('peerexecute',lang)+' · '+remote+' · inboundapply'
            self.assertTrue(any(message('confirm',lang,operation=expected) in line for line in output))
        self.api.request.assert_not_called()

    def test_terminal_escape_sequences_are_not_rendered(self):
        ui,output=self.console([])
        ui.describe({'note':'user\x1b[2J\r\ntext','unknown_field':True})
        self.assertNotIn('\x1b',''.join(output))

    def test_eof_exits_without_mutation(self):
        ui=Console(self.manager,read=Mock(side_effect=EOFError),write=Mock())
        ui.run()
        self.assertFalse(self.manager.certificates.path.exists())

    def test_inbound_form_creates_and_applies_without_json_in_three_languages(self):
        from atlant_control_demo import DemoAPI
        for lang in LANGUAGES:
            self.manager.api=DemoAPI()
            ui,output=self.console(['cli-'+lang,'CLI name','127.0.0.1:2026','192.0.2.5:2026','www.example.com','','true','true','false','true','0','0','false','yes'],lang)
            ui.edit_inbound(False)
            saved=self.manager.execute(self.manager.prepare('inbounds'))
            created=next(record for record in saved['inbounds'] if record['settings']['id']=='cli-'+lang)
            self.assertEqual(['tcp','quic'],created['settings']['transports'])
            self.assertEqual(1,saved['applied_revision'])
            ui,_=self.console(['yes'],lang)
            ui.apply_inbounds()
            self.assertEqual(2,self.manager.execute(self.manager.prepare('inbounds'))['applied_revision'])
            self.assertIn(message('inbound_key_notice',lang),output)

    def test_unified_subscriber_form_creates_credentials_and_quota(self):
        from atlant_control_demo import DemoAPI
        for lang in LANGUAGES:
            self.manager.api=DemoAPI()
            ui,output=self.console(['Subscriber '+lang,'true','2','Personal client','','1','0.1','1','yes'],lang)
            ui.edit_subscriber(False)
            record=self.manager.api.subscriptions[-1]
            self.assertTrue(record['managed'])
            self.assertEqual(2,record['ip_limit'])
            self.assertEqual('Personal client',record['note'])
            self.assertEqual(107374182,record['total_limit'])
            self.assertEqual([{'server_id':'d'*32,'inbound_id':'default'}],record['inbound_refs'])
            self.assertIn('sub-'+record['id'],self.manager.api.users)

    def test_migration_form_requires_selection_and_confirmation_in_three_languages(self):
        from atlant_control_demo import DemoAPI
        for lang in LANGUAGES:
            self.manager.api=DemoAPI()
            ui,output=self.console(['1','yes'],lang)
            ui.migrate_subscriptions()
            self.assertTrue(self.manager.api.subscriptions[0]['managed'])
            self.assertIn(message('migration_notice',lang),output)

    def test_inbound_tuning_form_in_three_languages(self):
        from atlant_control_demo import DemoAPI
        for lang in LANGUAGES:
            self.manager.api=DemoAPI()
            answers=['tuned-'+lang,'Tuned','127.0.0.1:2027','192.0.2.5:2027','www.example.com','/custom',
                     'true','true','true','true','0','0','true','90','7','12','48','8','false','4096','8','17','yes']
            ui,output=self.console(answers,lang)
            ui.edit_inbound(False)
            record=self.manager.api.inbounds['inbounds'][-1]['settings']
            self.assertEqual(12,record['quic']['stream_receive_window_mb'])
            self.assertEqual(48,record['quic']['conn_receive_window_mb'])
            self.assertEqual(4096,record['yamux']['max_stream_window_kb'])
            self.assertEqual(17,record['yamux']['write_timeout_sec'])
            self.assertIn(message('tuning_defaults',lang),output)

    def test_language_choice_is_saved_and_invalid_preference_is_ignored(self):
        ui,_=self.console(['3'])
        ui.languages()
        self.assertEqual('zh',saved_language(self.temp.name,'en'))
        self.assertEqual('zh',self.manager.language)
        (self.manager.state/'console-preferences.json').write_text('{"language":"invalid"}')
        self.assertEqual('en',saved_language(self.temp.name,'en'))

    def test_panel_address_form_saves_without_json_on_all_languages(self):
        for lang in LANGUAGES:
            ui,output=self.console(['3','127.0.0.1','9091','http://127.0.0.1:9091','yes'],lang)
            ui.panel_settings()
            self.assertEqual(9091,self.manager.panel_settings.read()['settings']['port'])
            self.assertIn(message('panel_saved_notice',lang),output)
        self.api.request.assert_not_called()

    def test_prompt_does_not_render_control_sequences_from_server_notes(self):
        ui,output=self.console([''])
        self.assertEqual('raw\x1b[2J',ui.ask('note','raw\x1b[2J'))
        self.assertNotIn('\x1b',''.join(output))

    def test_cli_help_defaults_to_english_but_respects_saved_cli_preference(self):
        config=Path(self.temp.name)/'client.json'
        private_write(config,{'state_dir':self.temp.name,'language':'zh'})
        output=io.StringIO()
        with patch('sys.argv',['atlantctl','--config',str(config),'help']),patch('sys.stdout',output):main()
        self.assertIn('Atlant management commands.',output.getvalue())
        private_write(Path(self.temp.name)/'console-preferences.json',{'language':'ru'})
        output=io.StringIO()
        with patch('sys.argv',['atlantctl','--config',str(config),'help']),patch('sys.stdout',output):main()
        self.assertIn('Команды Atlant',output.getvalue())
