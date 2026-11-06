"""Release-scope regression tests, including real Git diff edge cases."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('changes', Path(__file__).resolve().parents[2] / 'scripts/ci/changes.py')
changes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(changes)


class Scopes(unittest.TestCase):
    def test_lanes(self):
        cases = [
            (['ui/src/pages/ExplorePage.vue'], {'frontend'}),
            (['edge/frontend/src/index.ts'], {'frontend'}),
            (['src/nous/api.py'], {'python', 'backend_image'}),
            (['reports/site/package-lock.json'], {'python', 'reports', 'report_image'}),
            (['reports/templates/security-daily.yaml'], {'python', 'reports', 'report_image', 'backend_image'}),
            (['docs/ARCHITECTURE.md', 'README.md'], set()),
            (['ui/src/app.ts', 'src/nous/api.py'], {'frontend', 'python', 'backend_image'}),
            (['pyproject.toml'], {'python', 'backend_image', 'reports', 'report_image'}),
            (['src/nous/report_pipeline.py'], {'python', 'reports', 'report_image'}),
            (['src/nous/access_auth.py'], {'frontend', 'python', 'backend_image'}),
            (['deploy/cloudflare/terraform/main.tf'], {'terraform'}),
            (['.github/workflows/ci.yml'], set(changes.SCOPES)),
            (['new-shared-build-input'], set(changes.SCOPES)),
        ]
        for paths, expected in cases:
            with self.subTest(paths=paths):
                self.assertEqual({k for k, v in changes.classify(paths).items() if v}, expected)

    def test_git_ranges_first_push_rename_delete_and_multiple_commits(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], text=True)
            git('init', '-q')
            git('config', 'user.email', 'ci@example.invalid')
            git('config', 'user.name', 'CI fixture')
            root = Path(directory)
            (root / 'ui').mkdir()
            (root / 'ui/old.ts').write_text('UI')
            git('add', '.')
            git('commit', '-qm', 'base')
            base = git('rev-parse', 'HEAD').strip()
            (root / 'ui/old.ts').rename(root / 'backend.py')
            git('add', '-A')
            git('commit', '-qm', 'rename out of UI')
            (root / 'docs').mkdir()
            (root / 'docs/new.md').write_text('docs')
            git('add', '.')
            git('commit', '-qm', 'second pushed commit')
            head = git('rev-parse', 'HEAD').strip()
            with patch.object(changes, 'git', git):
                paths = changes.changed_paths({'before': base, 'after': head}, 'push')
                self.assertEqual(set(paths), {'ui/old.ts', 'backend.py', 'docs/new.md'})
                self.assertIn('ui/old.ts', changes.changed_paths({'before': '0' * 40, 'after': base}, 'push'))
                pr = {'pull_request': {'base': {'sha': base}, 'head': {'sha': head}}}
                self.assertEqual(paths, changes.changed_paths(pr, 'pull_request'))
            # Mainline merge compares first parent to merged tree, not HEAD~1
            # heuristics that omit multiple commits in a push.
            git('checkout', '-qb', 'mainline', base)
            git('merge', '--no-ff', '-qm', 'merge', head)
            merged = git('rev-parse', 'HEAD').strip()
            with patch.object(changes, 'git', git):
                self.assertEqual(set(paths), set(changes.changed_paths({'before': base, 'after': merged}, 'push')))

    def test_failed_release_changes_are_carried_into_next_push(self):
        # Newest commit is backend-only, but the previous UI commit has not
        # completed a successful main CI/release: both lanes must run.
        with patch.object(changes, 'revision', lambda sha: sha), patch.object(
            changes, 'git', side_effect=['src/nous/api.py\0', 'src/nous/api.py\0ui/app.ts\0']
        ):
            paths = changes.changed_paths({'before': 'b' * 40, 'after': 'c' * 40}, 'push', 'a' * 40)
        scopes = changes.classify(paths)
        self.assertTrue(scopes['frontend'])
        self.assertTrue(scopes['backend_image'])

    def test_report_runtime_dependency_changes_rebuild_report_image(self):
        import ast
        root = Path(__file__).resolve().parents[2] / 'src/nous'
        pending = ['report_worker']
        visited = set()
        while pending:
            name = pending.pop()
            if name in visited:
                continue
            visited.add(name)
            path = root / f'{name}.py'
            self.assertTrue(changes.classify([f'src/nous/{name}.py'])['report_image'], name)
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                    dependency = node.module.split('.')[0]
                    if (root / f'{dependency}.py').is_file():
                        pending.append(dependency)
