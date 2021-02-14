package com.security.authentication.server;

import com.security.authentication.command.CommandCreator;
import com.security.authentication.command.CommandExecutor;
import com.security.authentication.defend.Defender;
import com.security.authentication.exceptions.server.AcceptConnectionFailException;
import com.security.authentication.exceptions.server.ReadFailException;
import com.security.authentication.exceptions.server.ServerConfigurationFailException;
import com.security.authentication.exceptions.server.StorageConfigurationFailException;
import com.security.authentication.exceptions.server.WriteFailException;
import com.security.authentication.generator.Generator;
import com.security.authentication.generator.SecretKeyGenerator;
import com.security.authentication.handler.UserHandler;
import com.security.authentication.log.AuditLog;
import com.security.authentication.log.Log;
import com.security.authentication.storage.FileSystemStorage;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Set;

public class AuthenticationServer {
    private boolean isServerWorking;
    private Selector selector;
    private ByteBuffer buffer;
    private static final int BUFFER_SIZE = 2048;
    private final int port;
    private static final String HOST = "localhost";
    private final CommandExecutor commandExecutor;
    private final UserHandler userHandler;
    private Log log;

    {
        try {
            this.configureStorages();
        } catch (Exception e) {
            throw new StorageConfigurationFailException("failed to configure storages", e);
        }
    }

    public AuthenticationServer(int port) {
        this.userHandler = new UserHandler(new FileSystemStorage(Path.of("users.txt"), extractKey("secretKey.txt")));
        this.commandExecutor = new CommandExecutor(log, userHandler, new Defender());
        this.port = port;
    }

    public void start() {
        try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
            selector = Selector.open();

            try {
                configureServerSocketChannel(serverSocketChannel, selector);
            } catch (IOException e) {
                throw new ServerConfigurationFailException("Server failed to load", e);
            }

            buffer = ByteBuffer.allocate(BUFFER_SIZE);
            isServerWorking = true;

            while (isServerWorking) {
                int readyChannels = selector.select(10);

                if (readyChannels <= 0) {
                    continue;
                }

                Set<SelectionKey> selectedKeys = selector.selectedKeys();
                Iterator<SelectionKey> keyIterator = selectedKeys.iterator();

                while (keyIterator.hasNext()) {
                    SelectionKey key = keyIterator.next();
                    if (key.isReadable()) {
                        readKey(key);
                    } else if (key.isAcceptable()) {
                        try {
                            acceptKey(key);
                        } catch (IOException e) {
                            throw new AcceptConnectionFailException("could not accept client", e);
                        }

                    }
                    keyIterator.remove();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Error occurred while loading the server", e);
        }
    }

    public void stop() {
        this.isServerWorking = false;

        if (selector.isOpen()) {
            selector.wakeup();
        }
    }

    private void writeClientOutput(SocketChannel channel, String output) throws IOException {
        this.buffer.clear();
        this.buffer.put((output + System.lineSeparator()).getBytes(StandardCharsets.UTF_8));
        this.buffer.flip();
        channel.write(buffer);
    }

    private String getClientInput(SocketChannel channel) throws IOException {
        buffer.clear();
        int readBytes = channel.read(buffer);

        if (readBytes == -1) {
            return null;
        }

        buffer.flip();
        return StandardCharsets.UTF_8.decode(buffer).toString().trim();
    }

    private void readKey(SelectionKey key) {
        SocketChannel channel = (SocketChannel) key.channel();
        String clientInput;

        try {
            clientInput = getClientInput(channel);
        } catch (IOException e) {
            throw new ReadFailException("Failed to read input from client", e);
        }

        if (clientInput != null) {
            String output = commandExecutor.execute(CommandCreator.newCommand(clientInput), channel);

            try {
                writeClientOutput(channel, output);
            } catch (IOException e) {
                throw new WriteFailException("Failed to write to client", e);
            }
        }
    }

    private void acceptKey(SelectionKey key) throws IOException {
        ServerSocketChannel ssc = (ServerSocketChannel) key.channel();
        SocketChannel channel = ssc.accept();
        channel.configureBlocking(false);
        channel.register(selector, SelectionKey.OP_READ);
    }

    private void configureServerSocketChannel(ServerSocketChannel channel, Selector selector) throws IOException {
        channel.bind(new InetSocketAddress(HOST, this.port));
        channel.configureBlocking(false);
        channel.register(selector, SelectionKey.OP_ACCEPT);
    }

    private void configureStorages() throws Exception {
        if (!Files.exists(Path.of("users.txt"))) {
            Files.createFile(Path.of("users.txt"));
        }

        if (!Files.exists(Path.of("LOG.txt"))) {
            Files.createFile(Path.of("LOG.txt"));
        }

        if (!Files.exists(Path.of("secretKey.txt"))) {
            Files.createFile(Path.of("secretKey.txt"));

            Generator<SecretKey> secretKeyGenerator = new SecretKeyGenerator();
            SecretKey secretKey = secretKeyGenerator.generate();
            FileOutputStream fileOut = new FileOutputStream("secretKey.txt");
            ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
            objectOut.writeObject(secretKey);
            objectOut.close();
        }

        log = new AuditLog(new BufferedReader(new FileReader("LOG.txt")),
                new BufferedWriter(new FileWriter("LOG.txt", true)));
    }

    private SecretKey extractKey(String path) {
        try {
            FileInputStream fileIn = new FileInputStream(path);
            ObjectInputStream objectIn = new ObjectInputStream(fileIn);

            Object obj = objectIn.readObject();
            objectIn.close();

            return (SecretKey) obj;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) {
        AuthenticationServer server = new AuthenticationServer(4444);
        Thread serverThread = new Thread(server::start);
        serverThread.start();
    }
}