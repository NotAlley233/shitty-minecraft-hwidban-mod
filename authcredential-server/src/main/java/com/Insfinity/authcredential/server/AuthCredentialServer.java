package com.Insfinity.authcredential.server;

import com.Insfinity.authcredential.server.networking.AuthPayload;
import java.nio.file.Path;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.loader.api.FabricLoader;
import com.mojang.brigadier.arguments.StringArgumentType;
import net.minecraft.server.command.ServerCommandSource;
import net.minecraft.text.Text;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static net.minecraft.server.command.CommandManager.argument;
import static net.minecraft.server.command.CommandManager.literal;

/** auth_credential 服务端验证模组入口。 */
public final class AuthCredentialServer implements ModInitializer {
   private static final Logger LOGGER = LoggerFactory.getLogger("auth_credential_server");

   @Override
   public void onInitialize() {
      Path configDir = FabricLoader.getInstance().getConfigDir().resolve("auth_credential_server");

      ServerKeys.init(configDir);
      ActivationStore.init(configDir);

      // 注册服务端接收 play C2S 的 auth_info_play 负载编解码
      PayloadTypeRegistry.playC2S().register(AuthPayload.PLAY_ID, AuthPayload.CODEC);

      // 登录挑战 + 响应校验
      AuthLoginHandler.register();

      // 进世界上报
      JoinReporter.register();

      // 激活记录管理命令
      registerCommands();

      LOGGER.info("auth_credential_server 已初始化；激活记录 {} 条。", ActivationStore.size());
      LOGGER.info("本服务器公钥 hex={}（客户端内嵌 serverPub 需与此一致）", ServerKeys.publicHex());
   }

   private void registerCommands() {
      CommandRegistrationCallback.EVENT.register((dispatcher, registryAccess, environment) ->
            dispatcher.register(literal("authcredential")
                  .requires(src -> src.hasPermissionLevel(2))
                  .then(literal("pubkey").executes(ctx -> {
                     ctx.getSource().sendFeedback(() -> Text.literal("服务器公钥 hex: " + ServerKeys.publicHex()), false);
                     return 1;
                  }))
                  .then(literal("list").executes(ctx -> {
                     ctx.getSource().sendFeedback(() -> Text.literal("当前激活记录数: " + ActivationStore.size()), false);
                     return 1;
                  }))
                  .then(literal("activate")
                        .then(argument("clientPubHex", StringArgumentType.greedyString())
                              .executes(ctx -> {
                                 String arg = StringArgumentType.getString(ctx, "clientPubHex");
                                 return activate(ctx.getSource(), arg.trim());
                              })))
            ));
   }

   private static int activate(ServerCommandSource src, String arg) {
      // 期望格式: <clientPubHex> <boundName> <deviceIdHex32>
      String[] parts = arg.split("\\s+");
      if (parts.length < 3) {
         src.sendFeedback(() -> Text.literal("用法: /authcredential activate <clientPubHex> <boundName> <deviceId32hex>"), false);
         return 0;
      }
      String clientPubHex = parts[0];
      String boundName = parts[1];
      String deviceId = parts[2];
      if (!clientPubHex.matches("(?i)[0-9a-f]{64}")) {
         src.sendFeedback(() -> Text.literal("clientPub 应为 64 位 hex"), false);
         return 0;
      }
      ActivationStore.activate(clientPubHex, boundName, deviceId, false, "管理员激活");
      src.sendFeedback(() -> Text.literal("已激活 clientPub 前缀=" + clientPubHex.substring(0, 8)
            + " boundName=" + boundName + " 剩余记录=" + ActivationStore.size()), false);
      return 1;
   }
}