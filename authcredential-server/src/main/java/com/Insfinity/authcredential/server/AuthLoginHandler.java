package com.Insfinity.authcredential.server;

import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.fabricmc.fabric.api.networking.v1.ServerLoginConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerLoginNetworking;
import net.minecraft.network.PacketByteBuf;
import net.minecraft.server.network.ServerLoginNetworkHandler;
import net.minecraft.text.Text;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 登录认证流程：
 *   1) QUERY_START 向每个登录连接下发 auth_credential:auth_query 挑战
 *      （内：challenge(16B)/nonce(long)/int/serverPub(32B)/serverSignature(64B)/int）
 *   2) 收到客户端 7 字段响应后：验客户端签名 + 校验 protoVer + 查激活记录
 *   3) 通过则放行登录，否则 disconnect。
 */
public final class AuthLoginHandler {
   private static final Logger LOGGER = LoggerFactory.getLogger("auth_credential_server");
   private static final SecureRandom RANDOM = new SecureRandom();

   private record Pending(CompletableFuture<Void> future, byte[] challenge, long nonce, byte[] serverPub) {
   }

   private static final ConcurrentMap<ServerLoginNetworkHandler, Pending> PENDING = new ConcurrentHashMap<>();

   private AuthLoginHandler() {
   }

   public static void register() {
      ServerLoginConnectionEvents.QUERY_START.register(AuthLoginHandler::onQueryStart);
      ServerLoginNetworking.registerGlobalReceiver(AuthIds.AUTH_QUERY, AuthLoginHandler::onQueryResponse);
      ServerLoginConnectionEvents.DISCONNECT.register((handler, server) -> PENDING.remove(handler));
   }

   private static void onQueryStart(ServerLoginNetworkHandler handler,
                                    net.minecraft.server.MinecraftServer server,
                                    net.fabricmc.fabric.api.networking.v1.LoginPacketSender sender,
                                    net.fabricmc.fabric.api.networking.v1.ServerLoginNetworking.LoginSynchronizer synchronizer) {
      byte[] challenge = new byte[16];
      RANDOM.nextBytes(challenge);
      long nonce = RANDOM.nextLong();
      byte[] serverPub = ServerKeys.getPublic();

      byte[] toSign = CryptoUtil.concatChallenge(serverPub, challenge, nonce);
      byte[] serverSig = ServerKeys.sign(toSign);

      Pending pending = new Pending(new CompletableFuture<>(), challenge, nonce, serverPub);
      PENDING.put(handler, pending);

      // 挂起登录主流程，直到收到响应并放行/断开
      synchronizer.waitFor(pending.future());

      PacketByteBuf buf = PacketByteBufs.create();
      buf.writeByteArray(challenge);
      buf.writeLong(nonce);
      buf.writeInt(2);                 // protoVer（客户端 readInt，忽略）
      buf.writeByteArray(serverPub);
      buf.writeByteArray(serverSig);
      buf.writeInt(2);                 // id（客户端 readInt，忽略）
      sender.sendPacket(AuthIds.AUTH_QUERY, buf);
   }

   private static void onQueryResponse(net.minecraft.server.MinecraftServer server,
                                       ServerLoginNetworkHandler handler,
                                       boolean understood,
                                       PacketByteBuf buf,
                                       ServerLoginNetworking.LoginSynchronizer loginSynchronizer,
                                       net.fabricmc.fabric.api.networking.v1.PacketSender sender) {
      Pending pending = PENDING.remove(handler);
      if (!understood) {
         sender.disconnect(Text.literal("此服务器需要 auth_credential 客户端验证"));
         return;
      }
      if (pending == null) {
         sender.disconnect(Text.literal("未被请求的登录查询"));
         return;
      }

      try {
         String boundName = buf.readString();
         boolean nameMatch = buf.readBoolean();
         String deviceId = buf.readString();
         boolean isVM = buf.readBoolean();
         int protoVer = buf.readVarInt();
         byte[] clientPub = buf.readByteArray();
         byte[] signature = buf.readByteArray();

         byte[] signed = CryptoUtil.concatResponse(pending.serverPub(), pending.challenge(), pending.nonce(),
               nameMatch, isVM, boundName, deviceId);
         boolean sigOk = CryptoUtil.verify(clientPub, signature, signed);

         if (clientPub.length != 32) {
            sender.disconnect(Text.literal("auth_credential 客户端公钥格式错误"));
            return;
         }
         if (protoVer != 2 || signature.length != 64 || !sigOk) {
            LOGGER.warn("[登录] 客户端签名校验失败 clientPub={} protoVer={}",
                  CryptoUtil.hex(clientPub), protoVer);
            sender.disconnect(Text.literal("auth_credential 签名校验失败"));
            return;
         }

         ActivationStore.ActivationResult ar = ActivationStore.check(clientPub, deviceId);
         if (!ar.ok()) {
            LOGGER.warn("[登录] 拒绝未激活凭证 clientPub={} deviceId={} detail={}",
                  CryptoUtil.hex(clientPub), deviceId, ar.detail());
            sender.disconnect(Text.literal(ar.detail()));
            return;
         }

         LOGGER.info("[登录] 认证通过 boundName={} nameMatch={} deviceId={} isVM={}",
               boundName, nameMatch, deviceId, isVM);
         pending.future().complete(null); // 放行
      } catch (Exception e) {
         LOGGER.warn("[登录] 验证数据异常", e);
         sender.disconnect(Text.literal("auth_credential 验证数据异常"));
      }
   }
}