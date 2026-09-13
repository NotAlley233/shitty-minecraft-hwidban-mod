package com.Insfinity.authcredential;

import com.Insfinity.authcredential.networking.AuthPayload;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.minecraft.util.Identifier;

public class AuthCredential implements ModInitializer {
   public static final String MOD_ID = "auth_credential";
   public static final Identifier AUTH_QUERY_LOGIN_ID = Identifier.of("auth_credential", "auth_query");
   public static final Identifier AUTH_INFO_PLAY_ID = Identifier.of("auth_credential", "auth_info_play");

   @Override
   public void onInitialize() {
      // 注册上报到服务器的 Play C2S 负载（auth_info_play）
      PayloadTypeRegistry.playC2S().register(AuthPayload.PLAY_ID, AuthPayload.CODEC);
   }
}