// Local signing helper. Uses pinned Dio URI normalization; NEVER sends requests.
// Reads private material locally and exports only the resulting request metadata.
import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';

void main(List<String> args) {
  if (args.length != 2) {
    stderr.writeln('Usage: dart run bin/sign_offline.dart REQUEST_JSON PRIVATE_MATERIAL_JSON');
    exitCode = 2;
    return;
  }
  try {
    final request = Map<String, dynamic>.from(jsonDecode(File(args[0]).readAsStringSync()) as Map);
    final material = Map<String, dynamic>.from(jsonDecode(File(args[1]).readAsStringSync()) as Map);
    final suffix = (material['request_signature'] as Map)['secret_suffix'] as String;
    final baseUrl = request['baseUrl'] as String;
    final path = request['path'] as String;
    final query = Map<String, dynamic>.from((request['queryParameters'] as Map?) ?? {});
    final timestamp = request['timestamp'];
    final nonce = request['nonce'];
    if (timestamp is! int || timestamp < 0 || nonce is! String || !RegExp(r'^[a-z]{3}$').hasMatch(nonce) || suffix.isEmpty) {
      throw ArgumentError('Invalid signing input');
    }
    if (query.containsKey('sign') || Uri.parse(path).queryParameters.containsKey('sign') || Uri.parse(baseUrl).queryParameters.containsKey('sign')) {
      throw ArgumentError('Remove existing sign parameters before signing');
    }
    final options = RequestOptions(baseUrl: baseUrl, path: path, queryParameters: query);
    final canonicalUri = options.uri.toString();
    final digest = md5.convert(utf8.encode('$canonicalUri@$timestamp@$nonce$suffix')).toString();
    final signature = '$timestamp-$nonce-$digest';
    options.queryParameters = {...query, 'sign': signature};
    stdout.writeln(jsonEncode({
      'canonicalUriBeforeSign': canonicalUri,
      'queryParameterName': 'sign', 'queryParameterValue': signature,
      'signedUri': options.uri.toString(),
      'networkRequestPerformed': false,
    }));
  } catch (_) {
    // Do not leak private JSON, URI tokens, paths or secret material through errors.
    stderr.writeln('Offline signing failed; check local input types and remove any existing sign parameter. No request was sent.');
    exitCode = 2;
  }
}
