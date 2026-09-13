package com.Insfinity.authcredential.server;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;

/**
 * 服务器自身 Ed25519 密钥对（登录时用于对 auth_query 挑战签名）。
 *
 * 首次启动自动生成并持久化到 config/auth_credential_server/server_keys.json。
 * 生成的公钥必须内嵌进客户端 mod（改 embed/keys.properties 的 serverPub.b64 后重编），
 * 否则原 mod 的「服务器身份校验」会把本服务器拒掉。
 */
public final class ServerKeys {
   private static byte[] privateKey;
   private static byte[] publicKey;
   private static Path file;

   private ServerKeys() {
   }

   public static synchronized void init(Path configDir) {
      try {
         file = configDir.resolve("server_keys.json");
         if (Files.exists(file)) {
            JsonObject o = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
            privateKey = Base64.getDecoder().decode(o.get("privateKey").getAsString());
            publicKey = Base64.getDecoder().decode(o.get("publicKey").getAsString());
         } else {
            KeyPair kp = CryptoUtil.generateKeyPair();
            byte[] pkcs8 = kp.getPrivate().getEncoded();
            byte[] x509 = kp.getPublic().getEncoded();
            privateKey = new byte[32];
            publicKey = new byte[32];
            System.arraycopy(pkcs8, pkcs8.length - 32, privateKey, 0, 32);
            System.arraycopy(x509, x509.length - 32, publicKey, 0, 32);
            save();
         }
      } catch (Exception e) {
         throw new IllegalStateException("服务器密钥加载/生成失败", e);
      }
   }

   public static byte[] getPublic() {
      return publicKey == null ? null : publicKey.clone();
   }

   public static byte[] sign(byte[] data) {
      return CryptoUtil.sign(privateKey, data);
   }

   public static String publicHex() {
      return CryptoUtil.hex(publicKey);
   }

   private static void save() {
      try {
         Files.createDirectories(file.getParent());
         JsonObject o = new JsonObject();
         o.addProperty("privateKey", Base64.getEncoder().encodeToString(privateKey));
         o.addProperty("publicKey", Base64.getEncoder().encodeToString(publicKey));
         Files.writeString(file, new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(o),
               StandardCharsets.UTF_8);
      } catch (Exception e) {
         throw new IllegalStateException("服务器密钥保存失败", e);
      }
   }
}