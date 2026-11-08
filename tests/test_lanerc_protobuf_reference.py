"""Compare our bounded parser with generated official protobuf classes.
All test data is synthetic. This tests wire compatibility, not the schema's
correspondence to a production response (the schema comes from static analysis).
"""
import importlib.util
import pathlib
import random
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import lanerc_play_proto as proto


class OfficialProtobufReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from grpc_tools import protoc
        except ImportError:
            raise unittest.SkipTest('grpcio-tools and protobuf required for independent reference tests')
        cls.folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.folder.cleanup)
        source = ROOT / 'analysis/lanerc/reconstructed_play_resolve.proto'
        code = protoc.main(['protoc', '-I' + str(source.parent), '--python_out=' + cls.folder.name, str(source)])
        if code:
            raise RuntimeError('Reference protoc compilation failed')
        generated = pathlib.Path(cls.folder.name) / 'reconstructed_play_resolve_pb2.py'
        spec = importlib.util.spec_from_file_location('lanerc_reference_pb2', generated)
        cls.pb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.pb)

    def test_generated_outer_messages_500_cases(self):
        rng = random.Random(20261108)
        alphabet = 'abc XYZ 雪日漫&/+%'
        for index in range(500):
            values = {
                'code': rng.randint(-(1 << 31), (1 << 31) - 1),
                'msg': ''.join(rng.choice(alphabet) for _ in range(rng.randint(0, 48))),
                'encrypted': bool(rng.getrandbits(1)),
                'data': rng.randbytes(rng.randint(0, 96)),
            }
            with self.subTest(index=index):
                self.assertEqual(proto.response(self.pb.PlayResolveResponse(**values).SerializeToString()), values)

    def test_generated_inner_messages_100_cases(self):
        rng = random.Random(24008)
        for index in range(100):
            url = 'https://example.invalid/' + ''.join(rng.choice('abc 雪/&%') for _ in range(index))
            expected = self.pb.PlayResolve(playUrl=url)
            self.assertEqual(proto.play_resolve(expected.SerializeToString()), {'playUrl': url})

    def test_known_field_wrong_wire_type_is_unknown_to_reference(self):
        # Field 1/code with wire type 2 is unknown, not a fatal schema error.
        wire = b'\x0a\x01x' + self.pb.PlayResolveResponse(code=200).SerializeToString()
        reference = self.pb.PlayResolveResponse.FromString(wire)
        self.assertEqual(proto.response(wire)['code'], reference.code)
        inner = b'\x08\x01' + self.pb.PlayResolve(playUrl='https://example.invalid/').SerializeToString()
        self.assertEqual(proto.play_resolve(inner)['playUrl'], self.pb.PlayResolve.FromString(inner).playUrl)

    def test_duplicate_scalar_last_value_and_unknown_fields(self):
        first = self.pb.PlayResolveResponse(code=403, msg='first').SerializeToString()
        second = self.pb.PlayResolveResponse(code=200, msg='last').SerializeToString()
        wire = first + b'\x7a\x03abc' + second  # Unknown field 15, length-delimited.
        reference = self.pb.PlayResolveResponse.FromString(wire)
        self.assertEqual(proto.response(wire)['code'], reference.code)
        self.assertEqual(proto.response(wire)['msg'], reference.msg)

    def test_defaults(self):
        self.assertEqual(proto.response(b''), {'code': self.pb.PlayResolveResponse().code, 'msg': '', 'encrypted': False, 'data': b''})


if __name__ == '__main__':
    unittest.main()
