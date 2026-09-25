import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from backend.probe_primitives_v4 import route_ncrh, extend_ncrh, sample_hop_ttl, consume_hop


class ProbePrimitivesV4Tests(unittest.TestCase):
    def test_js_python_route_and_hop_parity(self):
        script=Path(__file__).resolve().parents[3]/'D-MASH PWA/not_messenger/js/probe_primitives_v4.js'
        program='''const api=require(process.argv[1]);(async()=>{
const base=new Uint8Array(32).fill(7),route=new Uint8Array(32).fill(11);
const root=await api.routeNcrh(base,route);
console.log(JSON.stringify([root,await api.extendNcrh(base,root)]));
})().catch(()=>process.exit(1));'''
        actual=json.loads(subprocess.check_output(['node','-e',program,str(script)],timeout=10))
        root=route_ncrh(bytes([7])*32,bytes([11])*32)
        self.assertEqual(actual,[root,extend_ncrh(bytes([7])*32,root)])
        self.assertNotEqual(root,route_ncrh(bytes([7])*32,bytes([12])*32))
        self.assertNotEqual(root,route_ncrh(bytes([8])*32,bytes([11])*32))
        self.assertNotEqual(root,extend_ncrh(bytes([7])*32,(bytes([11])*32).hex()))

    def test_random_budget_and_monotonic_consumption(self):
        with patch('backend.probe_primitives_v4.secrets.randbelow',return_value=0) as random:
            self.assertEqual(sample_hop_ttl(),4)
            random.assert_called_once_with(12)
        with patch('backend.probe_primitives_v4.secrets.randbelow',return_value=11):
            self.assertEqual(sample_hop_ttl(),15)
        budget=15
        for _ in range(15):budget=consume_hop(budget)
        self.assertEqual(budget,0)
        with self.assertRaises(ValueError):consume_hop(budget)

    def test_invalid_inputs_fail_closed(self):
        for ttl in (True,False,0,16,-1,2.0,'4',None):
            with self.assertRaises(ValueError):consume_hop(ttl)
        for low,high in ((0,15),(4,16),(4,4),(5,4),(True,15)):
            with self.assertRaises(ValueError):sample_hop_ttl(low,high)
        for base,route in ((None,bytes(32)),(bytes(31),bytes(32)),(bytes(32),'00'*32)):
            with self.assertRaises(ValueError):route_ncrh(base,route)
        for value in ('AA'*32,'  '+'00'*31,'00'*31,None):
            with self.assertRaises(ValueError):extend_ncrh(bytes(32),value)
