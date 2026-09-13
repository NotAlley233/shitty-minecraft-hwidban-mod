package com.Insfinity.authcredential.server;

import com.Insfinity.authcredential.server.networking.AuthPayload;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Play/JOIN 上报接收：客户端每次进世界会上报 auth_info_play（7 字段）。
 * 这里验签并记录，作为登录阶段设备绑定之外的辅助信号（客户端自报，仅作参考）。
 */
public final class JoinReporter {
   private static final Logger LOGGER = LoggerFactory.getLogger("auth_credential_server");

   private JoinReporter() {
   }

   public static void register() {
      ServerPlayNetworking.registerGlobalReceiver(AuthPayload.PLAY_ID, (payload, context) -> {
         try {
            byte[] signed = CryptoUtil.concatJoin(ServerKeys.getPublic(),
                  payload.nameMatch(), payload.isVM(), payload.boundName(), payload.deviceId());
            boolean ok = CryptoUtil.verify(payload.clientPub(), payload.signature(), signed);
            LOGGER.info("[上报] player={} boundName={} nameMatch={} deviceId={} isVM={} sigVerify={}",
                  context.player().getGameProfile().getName(),
                  payload.boundName(), payload.nameMatch(), payload.deviceId(), payload.isVM(), ok);
         } catch (Exception e) {
            LOGGER.warn("[上报] 数据异常 player={}", context.player().getGameProfile().getName(), e);
         }
      });
   }
}