import unittest

import obelisk

from node import multisig


class TestMultisig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pubkeys_hex = (
            "035b175132eeb8aa6e8455b6f1c1e4b2784bea1add47a6ded7fc9fc6b7aff16700",
            "0351e400c871e08f96246458dae79a55a59730535b13d6e1d4858035dcfc5f16e2",
            "02d53a92e3d43db101db55e351e9b42b4f711d11f6a31efbd4597695330d75d250"
        )
        cls.pubkeys = tuple(key.decode('hex') for key in cls.pubkeys_hex)
        cls.client = obelisk.ObeliskOfLightClient("tcp://85.25.198.97:8081")

    @staticmethod
    def _finished_escrow(escrow, tx):
        buyer_sigs = escrow.release_funds(
            tx,
            "b28c7003a7b6541cd1cd881928863abac0eff85f5afb40ff5561989c9fb95fb2".decode("hex")
        )

        completed_tx = escrow.claim_funds(
            tx,
            "5b05667dac199c48051932f14736e6f770e7a5917d2994a15a1508daa43bc9b0".decode("hex"),
            buyer_sigs
        )
        print 'COMPLETED TX: ', completed_tx.serialize().encode("hex")

    def test_escrow(self):
        escrow = multisig.Escrow(
            self.client, self.pubkeys[0], self.pubkeys[1], self.pubkeys[2]
        )

        # TODO: Send to the bitcoin network
        escrow.initiate(
            "1Fufjpf9RM2aQsGedhSpbSCGRHrmLMJ7yY",
            lambda tx: self._finished_escrow(escrow, tx)
        )

    def _finished_msig(self, msig, tx):
        print tx
        print ''
        print tx.serialize().encode("hex")
        print ''
        sigs1 = msig.sign_all_inputs(
            tx,
            "b28c7003a7b6541cd1cd881928863abac0eff85f5afb40ff5561989c9fb95fb2".decode("hex")
        )

        sigs3 = msig.sign_all_inputs(
            tx,
            "b74dbef0909c96d5c2d6971b37c8c71d300e41cad60aeddd6b900bba61c49e70".decode("hex")
        )

        self.assertLess(len(msig.script), 255)
        for i, _ in enumerate(tx.inputs):
            script = "\x00"
            for sig in (sigs1[i], sigs3[i]):
                script += chr(len(sig)) + sig
            script += "\x4c"
            script += chr(len(msig.script)) + msig.script
            print "Script:", script.encode("hex")
            tx.inputs[i].script = script

        print tx
        print tx.serialize().encode("hex")

    def test_multisignature(self):
        msig = multisig.Multisig(self.client, 2, self.pubkeys)
        self.assertEqual('3G9Mb5ZnqAouLaXJnJufbRLbCt8NKt8DGo', msig.address)

        msig.create_unsigned_transaction(
            "1Fufjpf9RM2aQsGedhSpbSCGRHrmLMJ7yY",
            lambda tx: self._finished_msig(msig, tx)
        )


if __name__ == "__main__":
    unittest.main()
