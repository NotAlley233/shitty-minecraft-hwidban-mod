package com.Insfinity.authcredential.server.networking;

import com.Insfinity.authcredential.server.AuthIds;
import net.minecraft.network.PacketByteBuf;
import net.minecraft.network.codec.PacketCodec;
import net.minecraft.network.packet.CustomPayload;

/**
 * 服务端侧的 AuthPayload 记录，与客户端逐字节一致。
 *
 * 注意 protoVer 的读取用 readVarInt()：客户端在 play 通道用 writeVarInt(protoVer)
 * 序列化（其 AuthPayload.CODEC 的写侧为 writeVarInt），因此读侧必须用 readVarInt 才能对齐。
 */
public record AuthPayload(
      String boundName,
      boolean nameMatch,
      String deviceId,
      boolean isVM,
      int protoVer,
      byte[] clientPub,
      byte[] signature) implements CustomPayload {

   public static final CustomPayload.Id<AuthPayload> PLAY_ID =
         new CustomPayload.Id<>(AuthIds.AUTH_INFO_PLAY);

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
               buf.readVarInt(), buf.readByteArray(), buf.readByteArray()));

   @Override
   public Id<? extends CustomPayload> getId() {
      return PLAY_ID;
   }
}