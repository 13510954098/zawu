"""Run local/independent-library checks and record honest verification scope."""
import importlib.metadata
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
fixture_path = ROOT / 'analysis/lanerc/dart-reference-fixtures.json'
if not fixture_path.exists():
    raise SystemExit('Independent Dart fixtures must be generated before this check')
fixture = json.loads(fixture_path.read_text())
suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_lanerc*.py')
result = unittest.TextTestRunner(verbosity=2).run(suite)
report = {
    'scope': 'Offline synthetic cross-implementation checks, plus existing unit tests',
    'original_apk_executed': False,
    'production_api_validated': False,
    'guest_credentials_obtained': False,
    'private_recovered_material_used': False,
    'tests_run': result.testsRun,
    'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
    'passed_without_skips': result.wasSuccessful() and not result.skipped,
    'generated_protobuf_cases': {'outer_messages': 500, 'inner_messages': 100},
    'dart_uri_signature_cases': len(fixture['uriSignatures']),
    'dart_version': fixture['dartVersion'], 'dart_reference_libraries': fixture['libraries'],
    'apk_library_versions_confirmed': False,
    'python_reference_libraries': {name: importlib.metadata.version(name) for name in ['cryptography', 'protobuf', 'grpcio-tools']},
    'compatibility_fix': 'Known field numbers with unknown wire types are skipped like generated protobuf, instead of rejected',
    'limitations': 'Confirms agreement with the pinned public-library references and reconstructed schema, not live server acceptance or an exact APK library-version match',
}
output = ROOT / 'analysis/lanerc/reference-validation.json'
output.write_text(json.dumps(report, indent=2) + '\n')
if not report['passed_without_skips']:
    raise SystemExit(1)
