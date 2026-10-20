# Bounded Qt-loader classifier reused from native/platforms/android/ci-runtime.py.
# It does not run the former app harness or publish raw logcat.
import re

def classify_loader(text, apk_libraries=()):
    known = {
        'Use local Qt libs is false': 'QT_LIBS_DISABLED',
        'Failed to resolve the APK native libraries directory': 'APK_DIRECTORY_UNAVAILABLE',
        'The native libraries directory is null or empty': 'NATIVE_DIRECTORY_UNAVAILABLE',
        'The main library name is null or empty': 'MAIN_NAME_MISSING',
        'Loading main library failed': 'MAIN_LOAD_FAILED',
        'failed to load Qt libraries': 'QT_LIBRARY_LOAD_FAILED',
        "Can't load '": 'NATIVE_LIBRARY_LOAD_FAILED',
        'cannot locate symbol': 'NATIVE_SYMBOL_UNAVAILABLE',
        'is 32-bit instead of 64-bit': 'NATIVE_ABI_MISMATCH',
        'No ComponentInfo found for given Context': 'COMPONENT_METADATA_UNAVAILABLE',
        'Context is not an instance of Activity or Service': 'CONTEXT_UNSUPPORTED',
    }
    # QtLoader logs the caught Throwable under the same tag. Retain only
    # fixed reason/class enums and names already present in this exact APK.
    allowed = {name for name in apk_libraries if re.fullmatch(r'lib[A-Za-z0-9_.+\-]{1,160}\.so', name)}
    aliases = {name: name for name in allowed}
    aliases.update({name[3:-3]: name for name in allowed})
    failed = set()
    unknown = False
    for value in re.findall(r"Can't load '([^'\n]{1,1024})'", text):
        name = aliases.get(value.rsplit('/', 1)[-1])
        if name is None:
            unknown = True
        else:
            failed.add(name)
    throwable_classes = ('UnsatisfiedLinkError', 'SecurityException', 'IllegalArgumentException',
                         'ExceptionInInitializerError', 'NoClassDefFoundError')
    reasons = {
        'dlopen failed': 'DLOPEN_FAILED',
        'cannot locate symbol': 'SYMBOL_UNAVAILABLE',
        'undefined symbol': 'SYMBOL_UNAVAILABLE',
        'JNI_ERR returned from JNI_OnLoad': 'JNI_ONLOAD_ERROR',
        'JNI_OnLoad returned bad version': 'JNI_ONLOAD_VERSION_INVALID',
        'not accessible for the namespace': 'NAMESPACE_DENIED',
        'not permitted for the namespace': 'NAMESPACE_DENIED',
        'failed to map segment': 'ELF_MAP_FAILED',
        'bad ELF magic': 'ELF_INVALID',
        'has text relocations': 'ELF_TEXT_RELOCATIONS',
        'is 32-bit instead of 64-bit': 'ELF_ABI_MISMATCH',
        'Permission denied': 'PERMISSION_DENIED',
        'No implementation found for': 'JNI_IMPLEMENTATION_UNAVAILABLE',
    }
    return {
        'events': [code for message, code in known.items() if message in text],
        'failedLibraries': sorted(failed),
        'unrecognizedFailingLibrary': unknown,
        'throwableClasses': [name for name in throwable_classes if 'java.lang.' + name + ':' in text],
        'reasons': sorted({code for phrase, code in reasons.items() if phrase in text}),
        'missingLibraries': sorted(set(re.findall(r'library "([A-Za-z0-9_.+\-]+\.so)" not found', text))),
    }
