package com.Insfinity.authcredential.tools;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * 构建期内嵌密钥 / ID 生成器。
 *
 * 还原原 mod 的密钥混淆机制：原始 jar 内每份密钥以 `byte[]` 形式内嵌，
 * 且并非明文，而是「先取 Base64/原始字符串的 UTF-8 字节，再逐字节 XOR 0x5E(94)」。
 * 运行时 `ServerBindingConfig.decode()` 再 XOR 回去得到 Base64 串，经 {@code a.le.dofuw}
 * 还原 32 字节密钥 / 明文 salt。
 *
 * 本工具读取 authcredential-client/embed/keys.properties，生成两个源码文件：
 *   ServerBindingConfig.java  —— 四条内嵌密钥数组（EXPSERVER_PUB / CLIENT_PRIVATE_KEY /
 *                                 CLIENT_PUBLIC_KEY / DEVICE_SALT）
 *   CredentialConfig.java     —— BOUND_PLAYER_NAME（内嵌 ID）
 *
 * 用法（由客户模块 build.gradle 的 `embedKeys` 任务调用）：
 *   KeyGen <目标源码目录> <keys.properties 路径>
 */
public final class KeyGen {
    private static final byte XOR_MASK = 94; // 0x5E，与原 jar 完全一致

    private KeyGen() {}

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            throw new IllegalArgumentException("用法: KeyGen <targetSourceDir> <keys.properties>");
        }
        Path targetDir = Paths.get(args[0]);
        Path propsPath = Paths.get(args[1]);

        Properties p = new Properties();
        try (var in = Files.newBufferedReader(propsPath, StandardCharsets.UTF_8)) {
            p.load(in);
        }

        String boundName = require(p, "boundName");
        String serverPubB64 = require(p, "serverPub.b64");
        String clientPrivB64 = require(p, "clientPriv.b64");
        String clientPubB64 = require(p, "clientPub.b64");
        String deviceSalt = require(p, "deviceSalt");

        // 校验形状，避免把错误输入写进 class
        byte[] sp = java.util.Base64.getDecoder().decode(serverPubB64);
        byte[] cpr = java.util.Base64.getDecoder().decode(clientPrivB64);
        byte[] cpu = java.util.Base64.getDecoder().decode(clientPubB64);
        if (sp.length != 32 || cpr.length != 32 || cpu.length != 32) {
            throw new IllegalArgumentException("公/私钥必须恰好 32 字节");
        }

        Files.createDirectories(targetDir);

        writeServerBindingConfig(targetDir, serverPubB64, clientPrivB64, clientPubB64, deviceSalt);
        writeCredentialConfig(targetDir, boundName);

        System.out.println("[KeyGen] 已生成 ServerBindingConfig.java / CredentialConfig.java");
        System.out.println("[KeyGen] boundName=" + boundName
                + " serverPub=" + hex(sp) + " clientPub=" + hex(cpu));
    }

    private static void writeServerBindingConfig(Path dir, String serverPubB64, String clientPrivB64,
                                                 String clientPubB64, String deviceSalt) throws IOException {
        String bob = "package com.Insfinity.authcredential;\n"
                + "\n"
                + "import com.Insfinity.authcredential.a.le;\n"
                + "import java.nio.charset.StandardCharsets;\n"
                + "\n"
                + "/** 由 keygen 在构建期自动生成（Base64/明文 -> UTF-8 -> XOR 0x5E 混淆）。请勿手改。 */\n"
                + "public final class ServerBindingConfig {\n"
                + "   private static final byte XOR_MASK = 94;\n"
                + "   public static final int PROTO_VERSION = 2;\n"
                + "   private static final byte[] EXPECTED_SERVER_PUB = new byte[]{" + arr(serverPubB64.getBytes(StandardCharsets.UTF_8)) + "};\n"
                + "   private static final byte[] CLIENT_PRIVATE_KEY = new byte[]{" + arr(clientPrivB64.getBytes(StandardCharsets.UTF_8)) + "};\n"
                + "   private static final byte[] CLIENT_PUBLIC_KEY = new byte[]{" + arr(clientPubB64.getBytes(StandardCharsets.UTF_8)) + "};\n"
                + "   private static final byte[] DEVICE_SALT = new byte[]{" + arr(deviceSalt.getBytes(StandardCharsets.UTF_8)) + "};\n"
                + "\n"
                + "   private ServerBindingConfig() {\n"
                + "   }\n"
                + "\n"
                + "   private static String decode(byte[] var0) {\n"
                + "      byte[] var1 = (byte[])var0.clone();\n"
                + "      for (int var2 = 0; var2 < var1.length; var2++) {\n"
                + "         var1[var2] = (byte)(var1[var2] ^ 94);\n"
                + "      }\n"
                + "      return new String(var1, StandardCharsets.UTF_8);\n"
                + "   }\n"
                + "\n"
                + "   public static byte[] getExpectedServerPub() {\n"
                + "      return le.dofuw(decode(EXPECTED_SERVER_PUB));\n"
                + "   }\n"
                + "   public static byte[] getClientPrivateKey() {\n"
                + "      return le.dofuw(decode(CLIENT_PRIVATE_KEY));\n"
                + "   }\n"
                + "   public static byte[] getClientPublicKey() {\n"
                + "      return le.dofuw(decode(CLIENT_PUBLIC_KEY));\n"
                + "   }\n"
                + "   public static String getDeviceSalt() {\n"
                + "      return decode(DEVICE_SALT);\n"
                + "   }\n"
                + "}\n";

        Path out = dir.resolve("ServerBindingConfig.java");
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out, StandardCharsets.UTF_8))) {
            w.print(bob);
        }
    }

    private static void writeCredentialConfig(Path dir, String boundName) throws IOException {
        String bob = "package com.Insfinity.authcredential;\n"
                + "\n"
                + "/** 由 keygen 在构建期自动生成。请勿手改。 */\n"
                + "public final class CredentialConfig {\n"
                + "   public static final String BOUND_PLAYER_NAME = \"" + boundName + "\";\n"
                + "\n"
                + "   private CredentialConfig() {\n"
                + "   }\n"
                + "}\n";

        Path out = dir.resolve("CredentialConfig.java");
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out, StandardCharsets.UTF_8))) {
            w.print(bob);
        }
    }

    /** 逐字节 XOR 0x5E 后输出源码 `(byte)NN, (byte)NN, ...`。原 jar 的混淆一致。 */
    private static String arr(byte[] utf8) {
        StringBuilder sb = new StringBuilder();
        for (byte b : utf8) {
            int v = (b ^ XOR_MASK) & 0xFF;
            sb.append("(byte)").append(v).append(", ");
        }
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 2); // 去掉末尾 ", "
        }
        return sb.toString();
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) {
            sb.append(String.format("%02X", v));
        }
        return sb.toString();
    }

    private static String require(Properties p, String key) {
        String v = p.getProperty(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("keys.properties 缺少字段: " + key);
        }
        return v.trim();
    }
}