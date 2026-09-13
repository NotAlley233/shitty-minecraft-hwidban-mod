package com.Insfinity.authcredential.server;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/** Ed25519 工具：签名 / 验签 / 消息拼接 / 密钥对生成 / XOR 0x5E 混淆。 */
public final class CryptoUtil {
   private static final byte[] ED25519_PUB_HEADER = new byte[]{48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0};
   private static final byte[] ED25519_PRIV_HEADER = new byte[]{48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32};

   private CryptoUtil() {
   }

   public static KeyPair generateKeyPair() throws Exception {
      KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
      g.initialize(256, new SecureRandom());
      return g.generateKeyPair();
   }

   public static PublicKey decodePublic(byte[] raw32) throws Exception {
      byte[] enc = new byte[ED25519_PUB_HEADER.length + 32];
      System.arraycopy(ED25519_PUB_HEADER, 0, enc, 0, ED25519_PUB_HEADER.length);
      System.arraycopy(raw32, 0, enc, ED25519_PUB_HEADER.length, 32);
      return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(enc));
   }

   public static PrivateKey decodePrivate(byte[] raw32) throws Exception {
      byte[] enc = new byte[ED25519_PRIV_HEADER.length + 32];
      System.arraycopy(ED25519_PRIV_HEADER, 0, enc, 0, ED25519_PRIV_HEADER.length);
      System.arraycopy(raw32, 0, enc, ED25519_PRIV_HEADER.length, 32);
      return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(enc));
   }

   /** 用服务器私钥（32 字节）签名。 */
   public static byte[] sign(byte[] rawPriv32, byte[] data) {
      try {
         Signature s = Signature.getInstance("Ed25519");
         s.initSign(decodePrivate(rawPriv32));
         s.update(data);
         return s.sign();
      } catch (Exception e) {
         throw new IllegalStateException("Ed25519 签名失败", e);
      }
   }

   /** 用公钥（32 字节）验证 64 字节签名。 */
   public static boolean verify(byte[] rawPub32, byte[] signature, byte[] data) {
      if (rawPub32 == null || rawPub32.length != 32 || signature == null || signature.length != 64) {
         return false;
      }
      try {
         Signature s = Signature.getInstance("Ed25519");
         s.initVerify(decodePublic(rawPub32));
         s.update(data);
         return s.verify(signature);
      } catch (Exception e) {
         return false;
      }
   }

   /** serverPub||challenge||nonce(BE 8) —— 服务器下发查询时的签名内容。 */
   public static byte[] concatChallenge(byte[] serverPub, byte[] challenge, long nonce) {
      return ByteBuffer.allocate(serverPub.length + challenge.length + 8)
            .put(serverPub).put(challenge).putLong(nonce).array();
   }

   /** 客户端响应的签名内容：serverPub||challenge||nonce||nameMatch||isVM||boundName||deviceId。 */
   public static byte[] concatResponse(byte[] serverPub, byte[] challenge, long nonce,
                                       boolean nameMatch, boolean isVM, String boundName, String deviceId) {
      byte[] bn = utf8(boundName);
      byte[] dv = utf8(deviceId);
      return ByteBuffer.allocate(serverPub.length + challenge.length + 8 + 2 + bn.length + dv.length)
            .put(serverPub).put(challenge).putLong(nonce)
            .put((byte) (nameMatch ? 1 : 0))
            .put((byte) (isVM ? 1 : 0))
            .put(bn).put(dv).array();
   }

   /** JOIN 上报的签名内容：serverPub||nameMatch||isVM||boundName||deviceId。 */
   public static byte[] concatJoin(byte[] serverPub, boolean nameMatch, boolean isVM,
                                   String boundName, String deviceId) {
      byte[] bn = utf8(boundName);
      byte[] dv = utf8(deviceId);
      return ByteBuffer.allocate(serverPub.length + 2 + bn.length + dv.length)
            .put(serverPub)
            .put((byte) (nameMatch ? 1 : 0))
            .put((byte) (isVM ? 1 : 0))
            .put(bn).put(dv).array();
   }

   /** 与原 jar 一致的「Base64/明文串 -> UTF-8 -> 逐字节 XOR 0x5E」混淆。 */
   public static byte[] xorEncode(byte[] utf8) {
      byte[] out = utf8.clone();
      for (int i = 0; i < out.length; i++) {
         out[i] ^= 94;
      }
      return out;
   }

   public static String hex(byte[] b) {
      if (b == null) return "null";
      StringBuilder sb = new StringBuilder(b.length * 2);
      for (byte v : b) sb.append(String.format("%02X", v));
      return sb.toString();
   }

   private static byte[] utf8(String s) {
      return (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
   }
}