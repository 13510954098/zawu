import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:encrypt/encrypt.dart' as enc;

// Public, synthetic inputs only. Never read the private recovery JSON here.
List<int> varint(int value) {
  final output = <int>[];
  while (value > 127) {
    output.add((value & 127) | 128);
    value >>= 7;
  }
  output.add(value);
  return output;
}

List<int> lengthDelimited(int number, List<int> value) =>
    [...varint((number << 3) | 2), ...varint(value.length), ...value];

void main(List<String> args) {
  if (args.length != 1) throw ArgumentError('Expected output JSON path');
  final keyBytes = List<int>.generate(32, (index) => index);
  final key = enc.Key(Uint8List.fromList(keyBytes));
  final nonceBytes = List<int>.generate(12, (index) => index);
  final nonce = enc.IV(Uint8List.fromList(nonceBytes));
  const playUrl = 'https://example.invalid/fixture.m3u8?name=%E9%9B%AA';
  final inner = lengthDelimited(1, utf8.encode(playUrl));
  final gcm = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
  final gcmPayload = gcm.encryptBytes(inner, iv: nonce).bytes;
  final binaryEnvelope = [...nonceBytes, ...gcmPayload];
  final outer = [0x08, ...varint(200), 0x18, 0x01, ...lengthDelimited(4, binaryEnvelope)];
  const ecbPlaintext = '{"fixture":"Dart to Python 雪","ok":true}';
  final ecb = enc.Encrypter(enc.AES(key, mode: enc.AESMode.ecb));
  final ecbCiphertext = ecb.encrypt(ecbPlaintext).base64;

  final cases = <Map<String, dynamic>>[
    {'name': 'basic', 'baseUrl': 'https://example.invalid/api/', 'path': 'app/config', 'query': <String, dynamic>{}},
    {'name': 'leading-slash', 'baseUrl': 'https://example.invalid/api/', 'path': '/app/config', 'query': <String, dynamic>{}},
    {'name': 'query-order-and-unicode', 'baseUrl': 'https://example.invalid/', 'path': 'search', 'query': <String, dynamic>{'q': '雪 空', 'page': 2, 'enabled': true}},
    {'name': 'list-and-null', 'baseUrl': 'https://example.invalid/', 'path': 'search', 'query': <String, dynamic>{'tags': ['日漫', 'a/b'], 'empty': '', 'none': null}},
    {'name': 'normalize-path', 'baseUrl': 'https://example.invalid/root/', 'path': '../a/./b/%2F', 'query': <String, dynamic>{'q': 'a+b & c'}},
    {'name': 'existing-query', 'baseUrl': 'https://example.invalid/', 'path': 'app/config?old=1', 'query': <String, dynamic>{'new': 'two words'}},
    {'name': 'absolute-url', 'baseUrl': 'https://example.invalid/unused/', 'path': 'https://EXAMPLE.invalid/direct', 'query': <String, dynamic>{'b': 2, 'a': 1}},
  ];
  const timestamp = 1700000000;
  const nonceText = 'abc';
  const suffix = 'fixture-suffix-17';
  final signatures = cases.map((test) {
    final options = RequestOptions(
      baseUrl: test['baseUrl'] as String,
      path: test['path'] as String,
      queryParameters: Map<String, dynamic>.from(test['query'] as Map),
    );
    final uri = options.uri.toString();
    final signaturePath = Uri.parse(uri).path;
    final digest = md5.convert(utf8.encode('$signaturePath@$timestamp@$nonceText$suffix')).toString();
    return {...test, 'canonicalUri': uri, 'nativeSignaturePath': signaturePath, 'timestamp': timestamp, 'nonce': nonceText,
      'syntheticSuffix': suffix, 'sign': '$timestamp-$nonceText-$digest'};
  }).toList();
  final result = {
    'scope': 'Independent public-library fixtures only; not original APK execution or production validation',
    'dartVersion': Platform.version.split(' ').first,
    'libraries': {'crypto': '3.0.6', 'dio': '5.9.0', 'encrypt': '5.0.3'},
    'apkLibraryVersionsConfirmed': false,
    'syntheticKeyHex': keyBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(),
    'gcm': {'nonceBytes': nonceBytes, 'plaintextProtoBase64': base64Encode(inner),
      'encryptedEnvelopeBase64': base64Encode(binaryEnvelope),
      'responseProtoBase64': base64Encode(outer), 'expectedPlayUrl': playUrl},
    'ecb': {'ciphertextBase64': ecbCiphertext, 'expectedPlaintext': ecbPlaintext},
    'uriSignatures': signatures,
  };
  final output = File(args.single);
  output.parent.createSync(recursive: true);
  output.writeAsStringSync('${const JsonEncoder.withIndent('  ').convert(result)}\n');
  stdout.writeln('Independent synthetic Dart fixtures generated; no private keys or APIs used');
}
