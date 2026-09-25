import base64
import json
import subprocess
from pathlib import Path
import unittest
from nacl.public import PrivateKey
from backend.recipient_payload_v4 import seal_payload,open_payload,cover_box
from backend.route_discovery_v4 import seal

class RecipientPayloadV4Tests(unittest.TestCase):
    def test_cover_is_discarded_without_losing_later_real_payload(self):
        recipient=PrivateKey.generate();previous=PrivateKey.generate()
        for size in (256,1024,16384):
            cover=cover_box(size)
            self.assertEqual(len(base64.b64decode(cover)),size)
            self.assertEqual(open_payload([recipient],cover),{'status':'discard'})
            self.assertEqual(open_payload(None,cover),{'status':'deferred'})
        real=seal_payload(recipient.public_key,'opaque Account envelope')
        result=open_payload([previous,recipient],real)
        self.assertEqual(result['status'],'accepted');self.assertEqual(result['payload'],'opaque Account envelope')
        self.assertEqual(len(result['packet_id']),64)
        self.assertEqual(open_payload([],real),{'status':'deferred'})
        self.assertEqual(open_payload([previous],real),{'status':'discard'})

    def test_configuration_errors_and_inner_schema_are_not_messages(self):
        recipient=PrivateKey.generate()
        for invalid in (False,0,'', [32], [bytes(31)], [bytes(32)]*3):
            with self.assertRaises(ValueError):open_payload(invalid,cover_box())
        for size in (True,255,16385,1.5):
            with self.assertRaises(ValueError):cover_box(size)
        for value in ({'payload':'not a valid envelope'}, {'type':'RECIPIENT_PAYLOAD','version':2,'packet_id':'aa'*32,'payload':'x','extra':True}):
            self.assertEqual(open_payload([recipient],seal(bytes(recipient.public_key),value)),{'status':'discard'})

    def test_real_js_python_payload_codec_parity(self):
        recipient=PrivateKey.generate()
        js=Path(__file__).resolve().parents[3]/'D-MASH PWA/not_messenger/js'
        program="""const fs=require('node:fs'),path=require('node:path'),root=process.argv[1];
        global.nacl=require(path.join(root,'vendor/nacl-fast.min.js'));
        require(path.join(root,'route_discovery_v4.js'));
        const api=require(path.join(root,'recipient_payload_v4.js')),input=JSON.parse(fs.readFileSync(0,'utf8'));
        const secret=new Uint8Array(Buffer.from(input.secret,'hex')),pair=nacl.box.keyPair.fromSecretKey(secret);
        process.stdout.write(JSON.stringify({opened:api.openPayload([secret],input.blob),blob:api.sealPayload(pair.publicKey,'from JS')}));
        secret.fill(0);pair.secretKey.fill(0);"""
        result=subprocess.run(['node','-e',program,str(js)],input=json.dumps(dict(secret=bytes(recipient).hex(),
            blob=seal_payload(recipient.public_key,'from Python'))),text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,'Recipient codec interop failed')
        output=json.loads(result.stdout)
        self.assertEqual(output['opened']['status'],'accepted');self.assertEqual(output['opened']['payload'],'from Python')
        self.assertEqual(open_payload([recipient],output['blob'])['payload'],'from JS')
