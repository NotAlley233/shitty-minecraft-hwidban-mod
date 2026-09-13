package com.Insfinity.authcredential.a;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Ed25519 签名 / 验签 / 消息拼接 / Base64 / 常量时间公钥比对。
 *
 * 注意：类名与私有方法名（le/rab/dofuw/kesih）保持与原 jar 一致——补丁模组
 * 通过 Mixin 以这些名字注入（如 a.le.rab([B[B)Z），改名会导致补丁失效。
 */
public final class le {
   private static final byte[] kesih = new byte[]{48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0};          // X509 Ed25519 公钥头
   private static final byte[] dofuw = new byte[]{48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32}; // PKCS8 Ed25519 私钥头

   private static PublicKey le(byte[] var0) {
      if (var0 != null && var0.length == 32) {
         byte[] var1 = new byte[kesih.length + 32];
         System.arraycopy(kesih, 0, var1, 0, kesih.length);
         System.arraycopy(var0, 0, var1, kesih.length, 32);
         try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(var1));
         } catch (Exception var3) {
            throw new IllegalStateException("Ed25519 公钥解析失败", var3);
         }
      } else {
         throw new IllegalArgumentException("Ed25519 公钥必须为 32 字节");
      }
   }

   private static PrivateKey rab(byte[] var0) {
      if (var0 != null && var0.length == 32) {
         byte[] var1 = new byte[dofuw.length + 32];
         System.arraycopy(dofuw, 0, var1, 0, dofuw.length);
         System.arraycopy(var0, 0, var1, dofuw.length, 32);
         try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(var1));
         } catch (Exception var3) {
            throw new IllegalStateException("Ed25519 私钥解析失败", var3);
         }
      } else {
         throw new IllegalArgumentException("Ed25519 私钥必须为 32 字节");
      }
   }

   /** 用 32 字节私钥对 data 签名，返回 64 字节签名；失败返回 null。 */
   public static byte[] le(byte[] var0, byte[] var1) {
      try {
         Signature var2 = Signature.getInstance("Ed25519");
         var2.initSign(rab(var1));
         var2.update(var0);
         return var2.sign();
      } catch (Exception var3) {
         System.err.println("[AuthCredential] Ed25519 签名失败: " + var3.getMessage());
         return null;
      }
   }

   /** 用 32 字节公钥验证 64 字节签名。 */
   public static boolean le(byte[] var0, byte[] var1, byte[] var2) {
      if (var1 != null && var1.length == 64 && var2 != null && var2.length == 32) {
         try {
            Signature var3 = Signature.getInstance("Ed25519");
            var3.initVerify(le(var2));
            var3.update(var0);
            return var3.verify(var1);
         } catch (Exception var4) {
            return false;
         }
      } else {
         return false;
      }
   }

   /** serverPub||challenge||nonce(long, 大端 8 字节) —— 登录查询里服务器签名的内容。 */
   public static byte[] le(byte[] var0, byte[] var1, long var2) {
      ByteBuffer var4 = ByteBuffer.allocate(var0.length + var1.length + 8);
      var4.put(var0).put(var1).putLong(var2);
      return var4.array();
   }

   /** 客户端响应的签名内容：serverPub||challenge||nonce||nameMatch||isVM||UTF8(boundName)||UTF8(deviceId)。 */
   public static byte[] le(byte[] var0, byte[] var1, long var2, boolean var4, boolean var5, String var6, String var7) {
      byte[] var8 = kesih(var6);
      byte[] var9 = kesih(var7);
      ByteBuffer var10 = ByteBuffer.allocate(var0.length + var1.length + 8 + 2 + var8.length + var9.length);
      var10.put(var0).put(var1).putLong(var2);
      var10.put((byte)(var4 ? 1 : 0));
      var10.put((byte)(var5 ? 1 : 0));
      var10.put(var8).put(var9);
      return var10.array();
   }

   /** JOIN 上报的签名内容：serverPub||nameMatch||isVM||UTF8(boundName)||UTF8(deviceId)。 */
   public static byte[] le(byte[] var0, boolean var1, boolean var2, String var3, String var4) {
      byte[] var5 = kesih(var3);
      byte[] var6 = kesih(var4);
      ByteBuffer var7 = ByteBuffer.allocate(var0.length + 2 + var5.length + var6.length);
      var7.put(var0);
      var7.put((byte)(var1 ? 1 : 0));
      var7.put((byte)(var2 ? 1 : 0));
      var7.put(var5).put(var6);
      return var7.array();
   }

   private static byte[] kesih(String var0) {
      return (var0 == null ? "" : var0).getBytes(StandardCharsets.UTF_8);
   }

   public static byte[] dofuw(String var0) {
      return Base64.getDecoder().decode(var0);
   }

   /** 常量时间字节相等比较。 */
   public static boolean rab(byte[] var0, byte[] var1) {
      if (var0 != null && var1 != null && var0.length == var1.length) {
         int var2 = 0;
         for (int var3 = 0; var3 < var0.length; var3++) {
            var2 |= var0[var3] ^ var1[var3];
         }
         return var2 == 0;
      } else {
         return false;
      }
   }
}