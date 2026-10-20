import importlib.util,json,pathlib,unittest
spec=importlib.util.spec_from_file_location('fork_loader',pathlib.Path(__file__).parents[1]/'ci/loader.py')
loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)
class LoaderClassification(unittest.TestCase):
    def test_apk_filename_and_fixed_reason(self):
        result=loader.classify_loader("Can't load 'dmash_credential_service_x86_64'\njava.lang.UnsatisfiedLinkError: dlopen failed",['libdmash_credential_service_x86_64.so'])
        self.assertEqual(result['failedLibraries'],['libdmash_credential_service_x86_64.so'])
        self.assertIn('DLOPEN_FAILED',result['reasons'])
    def test_unknown_details_are_not_published(self):
        detail='PRIVATE_RUNTIME_DETAIL_NOT_FOR_REPORT'
        result=loader.classify_loader("Can't load '"+detail+"'",['libdmash_credential_service_x86_64.so'])
        self.assertTrue(result['unrecognizedFailingLibrary'])
        self.assertNotIn(detail,json.dumps(result))
if __name__=='__main__':unittest.main()
