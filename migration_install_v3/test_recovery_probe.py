"""Ownership rejection cases; never start a builder or send a signal."""
import copy
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from . import recovery_probe as probe


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.path = Path('/evidence/attempts/app-build-0001/launched.json')
        self.work = Path('/work')
        self.prefix = '/work/attempts/app-build-0001'
        self.launch = dict(pid=401, pgid=401, stage='app-build', job_sha256='abc')
        self.job = dict(stage='app-build', launched=str(self.path), arguments=dict(out=self.prefix))
        self.members = [dict(pid=401, parent_pid=400, pgid=401,
            command='python3.13 -B -m migration_install_v3 _worker /evidence/attempts/app-build-0001/job.json --lock-fd 7'),
            dict(pid=402, parent_pid=401, pgid=401, command='clang -c '+self.prefix+'/native/runtime.c')]

    def eligible(self, launch=None, job=None, members=None):
        return probe.eligible_worker(self.path, self.launch if launch is None else launch,
            self.job if job is None else job, 'abc', self.work, 400,
            self.members if members is None else members)

    def test_owned_actual_compiler(self):
        self.assertEqual(self.eligible(), (401, Path(self.prefix), True))

    def test_no_compiler_waits(self):
        self.assertEqual(self.eligible(members=self.members[:1]), (401, Path(self.prefix), False))

    def test_wrong_parent_or_job_or_version(self):
        for key, value in [('parent_pid', 999), ('command', 'python3.13 -m migration_install_v2 _worker other.json')]:
            rows = copy.deepcopy(self.members); rows[0][key] = value
            with self.assertRaises(RuntimeError): self.eligible(members=rows)

    def test_wrong_group_bool_pid_or_hash(self):
        for key, value in [('pgid', 402), ('pid', True), ('job_sha256', 'different')]:
            launch = dict(self.launch); launch[key] = value
            with self.assertRaises(RuntimeError): self.eligible(launch=launch)

    def test_wrong_stage_path_or_output(self):
        for field, value in [('stage', 'graphics-build'), ('launched', '/unrelated/launched.json'),
                             ('arguments', dict(out='/old/product'))]:
            job = dict(self.job); job[field] = value
            with self.assertRaises(RuntimeError): self.eligible(job=job)

    def test_duplicate_or_escaped_member(self):
        with self.assertRaises(RuntimeError): self.eligible(members=self.members+self.members[:1])
        rows = copy.deepcopy(self.members); rows[1]['pgid'] = 777
        with self.assertRaises(RuntimeError): self.eligible(members=rows)

    def test_unrelated_compiler_is_not_eligible(self):
        rows = copy.deepcopy(self.members); rows[1]['command'] = 'clang -c /unrelated/source.c'
        self.assertFalse(self.eligible(members=rows)[2])

    def test_scoped_ps_reparse(self):
        text = '\n'.join('%s %s %s %s' % (r['pid'], r['parent_pid'], r['pgid'], r['command']) for r in self.members)
        self.assertEqual(probe.parse_members(text, 401), self.members)
        for bad in ('', '401 400', text+'\n'+text, '401 400 999 command'):
            with self.assertRaises(RuntimeError): probe.parse_members(bad, 401)

    def test_scoped_query_keeps_no_unrelated_argv(self):
        first = '401 400 401 worker\n402 401 401 clang\n999 998 999 unrelated-user-command\n'
        second = '401 400 401 worker\n402 401 401 clang\n'
        replies = [SimpleNamespace(stdout=t, stderr='', returncode=0) for t in (first, second)]
        with patch.object(probe.subprocess, 'run', side_effect=replies) as query:
            rows, raw = probe.group_members(401)
            self.assertEqual(raw['stdout'], second)
            self.assertEqual([r['pid'] for r in rows], [401, 402])
            self.assertEqual(query.call_args.args[0], ['/bin/ps', '-ww', '-p', '401,402', '-o', 'pid=,ppid=,pgid=,command='])

    def test_disappeared_compiler_resamples_without_signal(self):
        replies = [SimpleNamespace(stdout=t, stderr='', returncode=0)
                   for t in ('401 400 401 worker\n402 401 401 clang\n', '401 400 401 worker\n')]
        with patch.object(probe.subprocess, 'run', side_effect=replies), patch.object(probe.os, 'killpg') as signal:
            rows, raw = probe.group_members(401)
            self.assertIsNone(rows)
            signal.assert_not_called()

    def test_reused_pid_in_other_group_rejected(self):
        replies = [SimpleNamespace(stdout=t, stderr='', returncode=0)
                   for t in ('401 400 401 worker\n402 401 401 clang\n', '401 400 401 worker\n402 999 777 other\n')]
        with patch.object(probe.subprocess, 'run', side_effect=replies), patch.object(probe.os, 'killpg') as signal:
            with self.assertRaises(RuntimeError): probe.group_members(401)
            signal.assert_not_called()


if __name__ == '__main__':
    unittest.main()
