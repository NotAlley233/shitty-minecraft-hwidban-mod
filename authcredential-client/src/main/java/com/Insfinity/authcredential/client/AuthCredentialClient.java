package com.Insfinity.authcredential.client;

import com.Insfinity.authcredential.CredentialConfig;
import com.Insfinity.authcredential.ServerBindingConfig;
import com.Insfinity.authcredential.a.le;
import com.Insfinity.authcredential.networking.AuthPayload;
import java.util.concurrent.CompletableFuture;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.networking.v1.ClientLoginNetworking;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.minecraft.network.PacketByteBuf;

public class AuthCredentialClient implements ClientModInitializer {
   @Override
   public void onInitializeClient() {
      // ---- Login 查询接收器：接服务器下发 auth_query，校验身份后采集并回 7 字段 ----
      ClientLoginNetworking.registerGlobalReceiver(AuthPayload.LOGIN_ID.id(), (var0, var1, var2, var3) -> {
         byte[] challenge;
         long nonce;
         byte[] serverPub;
         byte[] serverSignature;
         try {
            challenge = var2.readByteArray();
            nonce = var2.readLong();
            int ignored1 = var2.readInt();
            serverPub = var2.readByteArray();
            serverSignature = var2.readByteArray();
            int ignored2 = var2.readInt();
         } catch (Exception var25) {
            return CompletableFuture.completedFuture(PacketByteBufs.create());
         }

         byte[] expected = ServerBindingConfig.getExpectedServerPub();
         boolean pubMatch = le.rab(expected, serverPub);
         byte[] toVerify = le.le(serverPub, challenge, nonce); // serverPub||challenge||longBE64
         boolean sigOk = le.le(toVerify, serverSignature, serverPub);
         if (pubMatch && sigOk) {
            String username = var0.getSession().getUsername();
            String bound = CredentialConfig.BOUND_PLAYER_NAME;
            boolean nameMatch = username.equals(bound);
            String deviceId = com.Insfinity.authcredential.client.le.le(); // client.le.le() 设备指纹
            boolean isVM = rab.dofuw();         // client.rab.dofuw() 虚拟机启发式
            byte[] clientPriv = ServerBindingConfig.getClientPrivateKey();
            byte[] clientPub = ServerBindingConfig.getClientPublicKey();
            byte[] toSign = le.le(serverPub, challenge, nonce, nameMatch, isVM, bound, deviceId);
            byte[] signature = le.le(toSign, clientPriv);
            if (signature == null) {
               return CompletableFuture.completedFuture(PacketByteBufs.create());
            }
            PacketByteBuf out = PacketByteBufs.create();
            out.writeString(bound);
            out.writeBoolean(nameMatch);
            out.writeString(deviceId);
            out.writeBoolean(isVM);
            out.writeVarInt(2);                 // protoVer
            out.writeByteArray(clientPub);
            out.writeByteArray(signature);
            return CompletableFuture.completedFuture(out);
         } else {
            System.err.println("[AuthCredential] 服务器身份校验失败（公钥不匹配或签名无效），已拒绝响应。");
            return CompletableFuture.completedFuture(PacketByteBufs.create());
         }
      });

      // ---- JOIN 回调：每次进入世界（含单人）直接上报 7 字段，不先验证服务器身份 ----
      ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
         String username = client.getSession().getUsername();
         String bound = CredentialConfig.BOUND_PLAYER_NAME;
         boolean nameMatch = username.equals(bound);
         String deviceId = com.Insfinity.authcredential.client.le.le();
         boolean isVM = rab.dofuw();
         byte[] serverPub = ServerBindingConfig.getExpectedServerPub();
         byte[] clientPriv = ServerBindingConfig.getClientPrivateKey();
         byte[] clientPub = ServerBindingConfig.getClientPublicKey();
         byte[] toSign = le.le(serverPub, nameMatch, isVM, bound, deviceId);
         byte[] signature = le.le(toSign, clientPriv);
         if (signature != null) {
            sender.sendPacket(new AuthPayload(bound, nameMatch, deviceId, isVM, 2, clientPub, signature), null);
         }
      });
   }
}