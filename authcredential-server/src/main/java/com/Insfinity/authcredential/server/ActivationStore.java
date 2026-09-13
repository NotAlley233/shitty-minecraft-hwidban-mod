package com.Insfinity.authcredential.server;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 激活记录存储（服务端不可被客户端绕过的事实依据）。
 *
 * 以客户端公钥 hex 为主键，记录该凭证允许绑定的 boundName / deviceId。
 * 持久化于 config/auth_credential_server/activation.json。
 * 未激活的 clientPub 一律登录拒绝（对应实战中的「该凭证未被激活」）。
 */
public final class ActivationStore {
   private static final class Record {
      String boundName;
      String deviceId;
      boolean isVM;
      String note;
      String activatedAt;

      Record() {
      }

      Record(String boundName, String deviceId, boolean isVM, String note) {
         this.boundName = boundName;
         this.deviceId = deviceId;
         this.isVM = isVM;
         this.note = note;
         this.activatedAt = Instant.now().toString();
      }
   }

   private static final Map<String, Record> RECORDS = new LinkedHashMap<>();
   private static Path file;

   private ActivationStore() {
   }

   public static synchronized void init(Path configDir) {
      try {
         file = configDir.resolve("activation.json");
         RECORDS.clear();
         if (Files.exists(file)) {
            JsonObject root = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
            JsonObject recs = root.getAsJsonObject("records");
            if (recs != null) {
               Gson g = new Gson();
               for (var e : recs.entrySet()) {
                  RECORDS.put(e.getKey(), g.fromJson(e.getValue(), Record.class));
               }
            }
         }
      } catch (Exception e) {
         throw new IllegalStateException("激活记录加载失败", e);
      }
   }

   public static synchronized void activate(String clientPubHex, String boundName, String deviceId,
                                            boolean isVM, String note) {
      RECORDS.put(clientPubHex.toUpperCase(), new Record(boundName, deviceId, isVM, note));
      save();
   }

   public static synchronized boolean isActivated(byte[] clientPub) {
      return RECORDS.containsKey(CryptoUtil.hex(clientPub));
   }

   /** 校验激活记录与上报的 deviceId 是否匹配。 */
   public static synchronized ActivationResult check(byte[] clientPub, String deviceId) {
      Record r = RECORDS.get(CryptoUtil.hex(clientPub));
      if (r == null) {
         return new ActivationResult(false, "该凭证未被激活");
      }
      if (r.deviceId != null && !r.deviceId.isEmpty() && !r.deviceId.equalsIgnoreCase(deviceId)) {
         return new ActivationResult(false, "设备指纹不匹配：该凭证已绑定其他设备");
      }
      return new ActivationResult(true, null);
   }

   public static synchronized int size() {
      return RECORDS.size();
   }

   private static void save() {
      try {
         Files.createDirectories(file.getParent());
         JsonObject recs = new JsonObject();
         Gson g = new Gson();
         for (var e : RECORDS.entrySet()) {
            recs.add(e.getKey(), g.toJsonTree(e.getValue()));
         }
         JsonObject root = new JsonObject();
         root.add("records", recs);
         Files.writeString(file, new GsonBuilder().setPrettyPrinting().create().toJson(root), StandardCharsets.UTF_8);
      } catch (Exception e) {
         throw new IllegalStateException("激活记录保存失败", e);
      }
   }

   public record ActivationResult(boolean ok, String detail) {
   }
}