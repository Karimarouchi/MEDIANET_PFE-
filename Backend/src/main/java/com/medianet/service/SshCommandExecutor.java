package com.medianet.service;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.medianet.entity.ServerNode;
import com.medianet.entity.SshAuthMethod;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Properties;
import java.util.function.Consumer;

@Service
public class SshCommandExecutor {

    private final TokenEncryptionService tokenEncryptionService;

    public SshCommandExecutor(TokenEncryptionService tokenEncryptionService) {
        this.tokenEncryptionService = tokenEncryptionService;
    }

    public CommandResult execute(ServerNode serverNode, String command, Duration timeout) throws Exception {
        return executeStreaming(serverNode, command, timeout, null);
    }

    public CommandResult executeStreaming(
            ServerNode serverNode,
            String command,
            Duration timeout,
            Consumer<String> logConsumer) throws Exception {
        Session session = openSession(serverNode);
        try {
            session.connect(15_000);
            ChannelExec channel = (ChannelExec) session.openChannel("exec");
            channel.setInputStream(null);
            channel.setCommand("bash -lc " + shellQuote("exec 2>&1\n" + command));

            InputStream stdout = channel.getInputStream();
            channel.connect(10_000);

            StringBuilder output = new StringBuilder();
            StringBuilder pendingLine = new StringBuilder();
            byte[] buffer = new byte[2048];
            long deadline = System.currentTimeMillis() + timeout.toMillis();

            while (true) {
                while (stdout.available() > 0) {
                    int read = stdout.read(buffer, 0, Math.min(buffer.length, stdout.available()));
                    if (read <= 0) {
                        break;
                    }
                    String chunk = new String(buffer, 0, read, StandardCharsets.UTF_8);
                    output.append(chunk);
                    appendChunk(chunk, pendingLine, logConsumer);
                }

                if (channel.isClosed()) {
                    while (stdout.available() > 0) {
                        int read = stdout.read(buffer, 0, Math.min(buffer.length, stdout.available()));
                        if (read <= 0) {
                            break;
                        }
                        String chunk = new String(buffer, 0, read, StandardCharsets.UTF_8);
                        output.append(chunk);
                        appendChunk(chunk, pendingLine, logConsumer);
                    }
                    flushPendingLine(pendingLine, logConsumer);
                    return new CommandResult(channel.getExitStatus(), output.toString().trim());
                }

                if (System.currentTimeMillis() >= deadline) {
                    channel.disconnect();
                    throw new IllegalStateException("Timeout while running remote command.");
                }

                Thread.sleep(120);
            }
        } finally {
            if (session.isConnected()) {
                session.disconnect();
            }
        }
    }

    private void appendChunk(String chunk, StringBuilder pendingLine, Consumer<String> logConsumer) {
        for (int index = 0; index < chunk.length(); index++) {
            char current = chunk.charAt(index);
            if (current == '\r') {
                continue;
            }
            if (current == '\n') {
                flushPendingLine(pendingLine, logConsumer);
                continue;
            }
            pendingLine.append(current);
        }
    }

    private void flushPendingLine(StringBuilder pendingLine, Consumer<String> logConsumer) {
        if (pendingLine.length() == 0) {
            return;
        }
        if (logConsumer != null) {
            logConsumer.accept(pendingLine.toString());
        }
        pendingLine.setLength(0);
    }

    private Session openSession(ServerNode serverNode) throws Exception {
        JSch jsch = new JSch();
        if (serverNode.getAuthMethod() == SshAuthMethod.PRIVATE_KEY) {
            byte[] privateKey = tokenEncryptionService.decrypt(serverNode.getEncryptedPrivateKey())
                    .getBytes(StandardCharsets.UTF_8);
            String passphrase = tokenEncryptionService.decrypt(serverNode.getEncryptedPrivateKeyPassphrase());
            jsch.addIdentity(
                    serverNode.getName(),
                    privateKey,
                    null,
                    passphrase != null ? passphrase.getBytes(StandardCharsets.UTF_8) : null);
        }

        Session session = jsch.getSession(serverNode.getUsername(), serverNode.getHost(), serverNode.getPort());
        if (serverNode.getAuthMethod() == SshAuthMethod.PASSWORD) {
            session.setPassword(tokenEncryptionService.decrypt(serverNode.getEncryptedPassword()));
        }
        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        config.put("PreferredAuthentications", "publickey,password,keyboard-interactive");
        session.setConfig(config);
        session.setTimeout(15_000);
        return session;
    }

    private String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    public record CommandResult(int exitCode, String output) {
    }
}
