package com.Insfinity.authcredential.server;

import net.minecraft.util.Identifier;

/** 通道 id 常量，与服务端协议一致。 */
public final class AuthIds {
   public static final String MOD_ID = "auth_credential_server";
   public static final Identifier AUTH_QUERY = Identifier.of("auth_credential", "auth_query");
   public static final Identifier AUTH_INFO_PLAY = Identifier.of("auth_credential", "auth_info_play");

   private AuthIds() {
   }
}