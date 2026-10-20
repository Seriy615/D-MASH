#!/usr/bin/env python3
"""Pure regression for Qt6.12 Log.e(message, Throwable) loader classification.
Examples follow the exact bundled QtLoader.loadLibraryHelper bytecode format;
these are fixtures, not a claim that a particular failure occurred on a device.
"""
import ast
import json
import pathlib
import re

source = pathlib.Path(__file__).with_name('ci-runtime.py').read_text()
function = next(node for node in ast.parse(source).body
                if isinstance(node, ast.FunctionDef) and node.name == 'classify_loader')
namespace = {'re': re}
exec(compile(ast.Module(body=[function], type_ignores=[]), '<classifier>', 'exec'), namespace)
classify = namespace['classify_loader']
libraries = ['libQt6Core_x86_64.so', 'libdmash_node_service_x86_64.so']

jni = "Can't load 'Qt6Core_x86_64'\njava.lang.UnsatisfiedLinkError: JNI_ERR returned from JNI_OnLoad in /private/random/libQt6Core_x86_64.so"
result = classify(jni, libraries)
assert result['failedLibraries'] == ['libQt6Core_x86_64.so']
assert result['throwableClasses'] == ['UnsatisfiedLinkError']
assert result['reasons'] == ['JNI_ONLOAD_ERROR']
assert result['events'] == ['NATIVE_LIBRARY_LOAD_FAILED']
assert not result['unrecognizedFailingLibrary']

symbol = "Can't load '/data/app/random/libdmash_node_service_x86_64.so'\njava.lang.UnsatisfiedLinkError: dlopen failed: cannot locate symbol \"private_arbitrary_details\" referenced by \"/private/path\""
result = classify(symbol, libraries)
assert result['failedLibraries'] == ['libdmash_node_service_x86_64.so']
assert result['reasons'] == ['DLOPEN_FAILED', 'SYMBOL_UNAVAILABLE']
assert 'private' not in json.dumps(result) and '/data' not in json.dumps(result)

unknown = "Can't load '/private/account-password-capability.so'\njava.lang.SecurityException: sensitive arbitrary details"
result = classify(unknown, libraries)
assert result['failedLibraries'] == [] and result['unrecognizedFailingLibrary']
assert result['throwableClasses'] == ['SecurityException']
assert 'password' not in json.dumps(result) and 'sensitive' not in json.dumps(result)
assert classify("Can't load 'libQt6Core_x86_64.so'", libraries)['failedLibraries'] == ['libQt6Core_x86_64.so']
assert classify("Can't load 'Qt6Core_x86_64'", ['../Qt6Core_x86_64'])['failedLibraries'] == []

# Original fixed diagnostic and missing-library behavior remains available.
result = classify('Loading main library failed\nlibrary "libcrypto_3.so" not found')
assert result['events'] == ['MAIN_LOAD_FAILED']
assert result['missingLibraries'] == ['libcrypto_3.so']
assert classify('', libraries) == dict(events=[], failedLibraries=[], unrecognizedFailingLibrary=False,
                                      throwableClasses=[], reasons=[], missingLibraries=[])
print('PASS Qt6.12 bounded loader classifier; no raw paths/exception details emitted')
