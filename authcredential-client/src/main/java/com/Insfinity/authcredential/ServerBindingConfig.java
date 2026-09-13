package com.Insfinity.authcredential;

import com.Insfinity.authcredential.a.le;
import java.nio.charset.StandardCharsets;

/** 由 keygen 在构建期自动生成（Base64/明文 -> UTF-8 -> XOR 0x5E 混淆）。请勿手改。 */
public final class ServerBindingConfig {
   private static final byte XOR_MASK = 94;
   public static final int PROTO_VERSION = 2;
   private static final byte[] EXPECTED_SERVER_PUB = new byte[]{(byte)51, (byte)22, (byte)14, (byte)113, (byte)56, (byte)46, (byte)41, (byte)108, (byte)46, (byte)9, (byte)14, (byte)57, (byte)24, (byte)63, (byte)56, (byte)24, (byte)36, (byte)61, (byte)50, (byte)52, (byte)56, (byte)18, (byte)52, (byte)29, (byte)17, (byte)50, (byte)44, (byte)29, (byte)10, (byte)61, (byte)20, (byte)29, (byte)117, (byte)51, (byte)29, (byte)40, (byte)43, (byte)40, (byte)31, (byte)109, (byte)15, (byte)103, (byte)102, (byte)99};
   private static final byte[] CLIENT_PRIVATE_KEY = new byte[]{(byte)107, (byte)19, (byte)39, (byte)4, (byte)51, (byte)48, (byte)24, (byte)29, (byte)111, (byte)46, (byte)48, (byte)110, (byte)45, (byte)102, (byte)57, (byte)106, (byte)117, (byte)103, (byte)31, (byte)8, (byte)53, (byte)29, (byte)58, (byte)61, (byte)7, (byte)103, (byte)48, (byte)59, (byte)19, (byte)41, (byte)14, (byte)27, (byte)54, (byte)113, (byte)6, (byte)117, (byte)19, (byte)111, (byte)61, (byte)60, (byte)29, (byte)9, (byte)27, (byte)99};
   private static final byte[] CLIENT_PUBLIC_KEY = new byte[]{(byte)47, (byte)42, (byte)117, (byte)42, (byte)61, (byte)21, (byte)102, (byte)39, (byte)9, (byte)12, (byte)18, (byte)40, (byte)51, (byte)23, (byte)11, (byte)50, (byte)50, (byte)117, (byte)47, (byte)7, (byte)27, (byte)9, (byte)43, (byte)63, (byte)45, (byte)44, (byte)110, (byte)9, (byte)48, (byte)49, (byte)39, (byte)43, (byte)63, (byte)13, (byte)28, (byte)16, (byte)20, (byte)42, (byte)23, (byte)17, (byte)31, (byte)105, (byte)57, (byte)99};
   private static final byte[] DEVICE_SALT = new byte[]{(byte)104, (byte)103, (byte)108, (byte)110, (byte)106, (byte)110, (byte)60, (byte)106, (byte)102, (byte)60, (byte)106, (byte)61, (byte)58, (byte)60, (byte)109, (byte)105, (byte)111, (byte)58, (byte)104, (byte)109, (byte)59, (byte)56, (byte)106, (byte)56, (byte)103, (byte)102, (byte)105, (byte)108, (byte)106, (byte)103, (byte)110, (byte)107, (byte)56, (byte)63, (byte)110, (byte)105, (byte)63, (byte)105, (byte)110, (byte)111, (byte)63, (byte)102, (byte)56, (byte)108, (byte)59, (byte)58, (byte)105, (byte)60, (byte)59, (byte)60, (byte)59, (byte)61, (byte)102, (byte)109, (byte)61, (byte)104, (byte)105, (byte)59, (byte)103, (byte)111, (byte)111, (byte)105, (byte)107, (byte)103};

   private ServerBindingConfig() {
   }

   private static String decode(byte[] var0) {
      byte[] var1 = (byte[])var0.clone();
      for (int var2 = 0; var2 < var1.length; var2++) {
         var1[var2] = (byte)(var1[var2] ^ 94);
      }
      return new String(var1, StandardCharsets.UTF_8);
   }

   public static byte[] getExpectedServerPub() {
      return le.dofuw(decode(EXPECTED_SERVER_PUB));
   }
   public static byte[] getClientPrivateKey() {
      return le.dofuw(decode(CLIENT_PRIVATE_KEY));
   }
   public static byte[] getClientPublicKey() {
      return le.dofuw(decode(CLIENT_PUBLIC_KEY));
   }
   public static String getDeviceSalt() {
      return decode(DEVICE_SALT);
   }
}
