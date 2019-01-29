package com.invaa;

import org.jose4j.jws.EcdsaUsingShaAlgorithm;
import org.jose4j.jws.JsonWebSignature;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.ec.ECPublicKeyImpl;

import java.security.*;
import java.util.Base64;

public class App {

private static final int SIGNATURE_SIZE = 64;
private static final String SHA_256_WITH_ECDSA = "SHA256withECDSA";
private static final String KEY_PUBLIC_BASE64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAagkAcOJW3jRhGW53iEqxEcfakh/X/"
        + "g9U334fM4xmSo/JMSHMBM80cnWpGF7DHRccgz0EqHIvaI+HDo93r2dwg==";

private static final String KEY_PRIVATE_BASE64 = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAEgpvK0j5YJFnYhL/" +
        "dmE2B4ZX75N0wsHCz7b78cdDARRkkGcnhphxwiMV95ADwO15sJKum26WFRJP4pAxotmlRLjjAELV+a/qVm4rSzQOHUlaJCW0m3ZRYDbgN4pU80PW";

private static final String JWT_PAYLOAD = "helloworld";

    public static void main(String ... args) throws Exception {
        PublicKey publicKey = getPublicKey(KEY_PUBLIC_BASE64);
        PrivateKey privateKey = getPrivateKey(KEY_PRIVATE_BASE64);

        String jwsHeaderAndPayload =
                Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"ES256\"}".getBytes()) + "."
                        + Base64.getUrlEncoder().withoutPadding().encodeToString(JWT_PAYLOAD.getBytes());

        String jwsStr = jwsHeaderAndPayload + "." +
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                EcdsaUsingShaAlgorithm.convertDerToConcatenated(
                                        sign(privateKey, jwsHeaderAndPayload.getBytes()), SIGNATURE_SIZE)
                        );

        JsonWebSignature jwsTest = new JsonWebSignature();
        jwsTest.setCompactSerialization(jwsStr);
        jwsTest.setKey(publicKey);
        System.out.println("Jws: " + jwsStr);
        System.out.println("Signature is valid: " + jwsTest.verifySignature());
    }


    private static PublicKey getPublicKey(String string) throws InvalidKeyException {
        return new ECPublicKeyImpl(Base64.getDecoder().decode(string));
    }

    private static PrivateKey getPrivateKey(String string) throws InvalidKeyException {
        return new ECPrivateKeyImpl(Base64.getDecoder().decode(string));
    }

    private static byte[] sign(PrivateKey privateKey, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SHA_256_WITH_ECDSA);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

}



