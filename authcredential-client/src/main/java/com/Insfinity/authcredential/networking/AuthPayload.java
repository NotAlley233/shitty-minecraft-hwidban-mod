package com.Insfinity.authcredential.networking;

import com.Insfinity.authcredential.AuthCredential;
import net.minecraft.network.PacketByteBuf;
import net.minecraft.network.codec.PacketCodec;
import net.minecraft.network.packet.CustomPayload;

/**
 * 认证负载，7 字段：boundName / nameMatch / deviceId / isVM / protoVer / clientPub(32B) / signature(64B)。
 *
 * 字段与顺序、编解码与原 mod 逐字节一致：
 *   writeString(boundName) writeBoolean(nameMatch) writeString(deviceId)
 *   writeBoolean(isVM) writeVarInt(protoVer=2) writeByteArray(clientPub) writeByteArray(signature)
 *
 * 注意：PLAY_ID 用于登录握手完成后的 JOIN 上报；LOGIN_ID 用于登录查询请求，由客户端 Login 接收器处理。
 */
public record AuthPayload(
      String boundName,
      boolean nameMatch,
      String deviceId,
      boolean isVM,
      int protoVer,
      byte[] clientPub,
      byte[] signature) implements CustomPayload {

   public static final CustomPayload.Id<AuthPayload> LOGIN_ID =
         new CustomPayload.Id<>(AuthCredential.AUTH_QUERY_LOGIN_ID);
   public static final CustomPayload.Id<AuthPayload> PLAY_ID =
         new CustomPayload.Id<>(AuthCredential.AUTH_INFO_PLAY_ID);

   public static final PacketCodec<PacketByteBuf, AuthPayload> CODEC = PacketCodec.of(
         (payload, buf) -> {
            buf.writeString(payload.boundName());
            buf.writeBoolean(payload.nameMatch());
            buf.writeString(payload.deviceId());
            buf.writeBoolean(payload.isVM());
            buf.writeVarInt(payload.protoVer());
            buf.writeByteArray(payload.clientPub());
            buf.writeByteArray(payload.signature());
         },
         buf -> new AuthPayload(
               buf.readString(), buf.readBoolean(), buf.readString(), buf.readBoolean(),
               buf.readInt(), buf.readByteArray(), buf.readByteArray()));

   @Override
   public Id<? extends CustomPayload> getId() {
      return PLAY_ID;
   }
}