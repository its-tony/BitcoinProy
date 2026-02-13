package BitcoinProy;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class PruebaP2PKH {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPair keyPair = generarParClaves();
        byte[] pubKeyComprimida = clavePublicaComprimida((BCECPublicKey) keyPair.getPublic());
        byte[] pubKeyHash160 = hash160(pubKeyComprimida);
        byte[] scriptPubKey = construirScriptPubKey(pubKeyHash160);

        // Simulacion de hash de transaccion.
        byte[] txHash = sha256("tx_de_prueba_p2pkh".getBytes(StandardCharsets.UTF_8));

        byte[] firmaDer = firmar(txHash, keyPair.getPrivate());
        byte[] scriptSig = construirScriptSig(firmaDer, pubKeyComprimida);
        boolean valido = verificarP2PKH(txHash, scriptSig, scriptPubKey);

        System.out.println("PubKeyHash160: " + hex(pubKeyHash160));
        System.out.println("scriptPubKey: " + hex(scriptPubKey));
        System.out.println("scriptSig:    " + hex(scriptSig));
        System.out.println("Resultado verificacion P2PKH: " + valido);
    }

    static KeyPair generarParClaves() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        return kpg.generateKeyPair();
    }

    static byte[] clavePublicaComprimida(BCECPublicKey pubKey) {
        return pubKey.getQ().getEncoded(true);
    }

    static byte[] construirScriptPubKey(byte[] pubKeyHash160) {
        // OP_DUP OP_HASH160 PUSH20 <pubKeyHash160> OP_EQUALVERIFY OP_CHECKSIG
        return concat(
                new byte[] {(byte) 0x76, (byte) 0xA9, 0x14},
                pubKeyHash160,
                new byte[] {(byte) 0x88, (byte) 0xAC}
        );
    }

    static byte[] construirScriptSig(byte[] firmaDer, byte[] pubKeyComprimida) {
        return concat(pushData(firmaDer), pushData(pubKeyComprimida));
    }

    static boolean verificarP2PKH(byte[] txHash, byte[] scriptSig, byte[] scriptPubKey) throws Exception {
        int i = 0;
        int lenFirma = scriptSig[i] & 0xFF;
        i++;
        byte[] firma = Arrays.copyOfRange(scriptSig, i, i + lenFirma);
        i += lenFirma;

        int lenPub = scriptSig[i] & 0xFF;
        i++;
        byte[] pubKey = Arrays.copyOfRange(scriptSig, i, i + lenPub);

        if (scriptPubKey.length != 25) return false;
        if ((scriptPubKey[0] & 0xFF) != 0x76) return false; // OP_DUP
        if ((scriptPubKey[1] & 0xFF) != 0xA9) return false; // OP_HASH160
        if ((scriptPubKey[2] & 0xFF) != 0x14) return false; // PUSH20
        if ((scriptPubKey[23] & 0xFF) != 0x88) return false; // OP_EQUALVERIFY
        if ((scriptPubKey[24] & 0xFF) != 0xAC) return false; // OP_CHECKSIG

        byte[] hashEsperado = Arrays.copyOfRange(scriptPubKey, 3, 23);
        byte[] hashReal = hash160(pubKey);
        if (!Arrays.equals(hashEsperado, hashReal)) return false;

        return verificarFirma(txHash, firma, pubKey);
    }

    static byte[] firmar(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("NONEwithECDSA", "BC");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    static boolean verificarFirma(byte[] data, byte[] firmaDer, byte[] pubKeyComprimida) throws Exception {
        PublicKey pub = reconstruirClavePublica(pubKeyComprimida);
        Signature signature = Signature.getInstance("NONEwithECDSA", "BC");
        signature.initVerify(pub);
        signature.update(data);
        return signature.verify(firmaDer);
    }

    static PublicKey reconstruirClavePublica(byte[] pubKeyComprimida) throws Exception {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        org.bouncycastle.math.ec.ECPoint point = params.getCurve().decodePoint(pubKeyComprimida);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, params);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        return keyFactory.generatePublic(pubSpec);
    }

    static byte[] sha256(byte[] input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    static byte[] hash160(byte[] input) throws Exception {
        byte[] sha = sha256(input);
        MessageDigest ripe = MessageDigest.getInstance("RIPEMD160", "BC");
        return ripe.digest(sha);
    }

    static byte[] pushData(byte[] data) {
        if (data.length > 75) {
            throw new IllegalArgumentException("Solo se maneja push directo <= 75 bytes");
        }
        return concat(new byte[] {(byte) data.length}, data);
    }

    static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) len += p.length;
        byte[] out = new byte[len];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
