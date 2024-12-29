package com.spring.ftp.server.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.beans.factory.annotation.Value;

import javax.annotation.PostConstruct;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HashMap;

@Slf4j
@Configuration
@Profile("server")
public class FtpServerConfig {

    @Value("${ftp.server.port:21}")
    private int port;

    @Value("${ftp.server.data-port:38017}")
    private int dataPort;

    @Value("#{${ftp.server.users}}")
    private Map<String, String> configuredUsers;

    @Value("${ftp.server.anonymous.enabled:true}")
    private boolean anonymousEnabled;

    @Value("${ftp.server.anonymous.upload:false}")
    private boolean anonymousUpload;

    @Value("${ftp.server.anonymous.home:/public}")
    private String anonymousHome;

    private final ExecutorService executorService = Executors.newCachedThreadPool();

    // 添加用户当前目录的跟踪
    private static class ClientSession {
        String username;
        String currentPath = "/";
        boolean isAnonymous;
    }
    
    private final Map<Socket, ClientSession> clientSessions = new ConcurrentHashMap<>();

    // 添加用户配置
    private final Map<String, String> userCredentials = new HashMap<>();

    @PostConstruct
    public void startServer() {
        // 初始化用户凭证
        initializeUsers();
        
        // 确保基本目录结构存在
        ensureDirectoryStructure();

        executorService.execute(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                serverSocket.setReuseAddress(true);
                log.info("FTP服务器已启动，监听端口: {}, 数据端口: {}", port, dataPort);
                while (true) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        log.info("接收到新的客户端连接: {}", clientSocket.getInetAddress());
                        handleClient(clientSocket);
                    } catch (IOException e) {
                        log.error("处理客户端连接时发生错误", e);
                    }
                }
            } catch (IOException e) {
                log.error("FTP服务器启动失败", e);
            }
        });
    }

    private void initializeUsers() {
        if (configuredUsers != null && !configuredUsers.isEmpty()) {
            userCredentials.putAll(configuredUsers);
            log.info("从配置文件加载了 {} 个用户账号", configuredUsers.size());
        } else {
            // 默认用户
            userCredentials.put("admin", "admin123");
            userCredentials.put("user", "user123");
            log.info("使用默认用户账号");
        }
        
        // 创建用户目录
        userCredentials.keySet().forEach(this::createUserDirectory);
    }

    private boolean authenticateUser(String username, String password) {
        String storedPassword = userCredentials.get(username);
        if (storedPassword != null && storedPassword.equals(password)) {
            log.debug("用户认证成功: {}", username);
            return true;
        }
        log.debug("用户认证失败: {}", username);
        return false;
    }

    private void setupDirectory(String path) {
        try {
            File dir = new File(path);
            if (!dir.exists() && dir.mkdirs()) {
                log.info("创建目录: {}", path);
            }
            
            // 使用 shell 命令设置权限
            ProcessBuilder pb = new ProcessBuilder(
                "sh", "-c",
                "chmod -R 777 " + path + " && " +
                "chown -R root:root " + path
            );
            Process process = pb.start();
            process.waitFor();
            
            log.info("目录权限设置完成: {}", path);
        } catch (Exception e) {
            log.error("设置目录权限失败: {}", path, e);
        }
    }

    private void handleClient(Socket clientSocket) {
        executorService.execute(() -> {
            ClientSession session = new ClientSession();
            clientSessions.put(clientSocket, session);
            
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter writer = new PrintWriter(
                    new OutputStreamWriter(clientSocket.getOutputStream()), true)) {

                writer.println("220 Welcome to FTP Server");
                String command;
                boolean isLoggedIn = false;

                while ((command = reader.readLine()) != null) {
                    log.debug("收到命令: {} (用户: {})", command, session.username);
                    String[] parts = command.split(" ", 2);
                    String cmd = parts[0].toUpperCase();
                    String arg = parts.length > 1 ? parts[1] : "";

                    switch (cmd) {
                        case "USER":
                            if (parts.length > 1) {
                                session.username = parts[1];
                                if ("anonymous".equalsIgnoreCase(session.username)) {
                                    if (anonymousEnabled) {
                                        session.isAnonymous = true;
                                        isLoggedIn = true;
                                        session.currentPath = anonymousHome;
                                        writer.println("230 Anonymous access granted");
                                        log.info("匿名用户登录成功");
                                    } else {
                                        writer.println("530 Anonymous access not allowed");
                                        log.info("匿名访问被禁止");
                                    }
                                } else {
                                    writer.println("331 User name okay, need password");
                                }
                            }
                            break;

                        case "PASS":
                            if (session.username != null && !session.isAnonymous) {
                                if (authenticateUser(session.username, parts.length > 1 ? parts[1] : "")) {
                                    isLoggedIn = true;
                                    session.currentPath = "/" + session.username;  // 设置用户的初始目录
                                    writer.println("230 User logged in, proceed");
                                } else {
                                    writer.println("530 Login incorrect");
                                }
                            } else if (session.isAnonymous) {
                                writer.println("230 Anonymous access granted");
                            } else {
                                writer.println("503 Login with USER first");
                            }
                            break;

                        case "PASV":
                            if (isLoggedIn) {
                                // 计算数据端口的高字节和低字节
                                int p1 = dataPort / 256;
                                int p2 = dataPort % 256;
                                // 获取服务器IP地址
                                String serverIP = clientSocket.getLocalAddress().getHostAddress();
                                String[] ipParts = serverIP.split("\\.");
                                // 返回PASV响应，格式：(h1,h2,h3,h4,p1,p2)
                                writer.println("227 Entering Passive Mode (" +
                                        String.join(",", ipParts) + "," + p1 + "," + p2 + ")");
                                log.debug("进入被动模式，数据端口: {}", dataPort);
                            } else {
                                writer.println("530 Not logged in");
                            }
                            break;

                        case "LIST":
                            if (isLoggedIn) {
                                String listPath = arg.isEmpty() ? session.currentPath : 
                                    resolvePath(session.currentPath, arg);
                                handleList(writer, listPath, session);
                            } else {
                                writer.println("530 Not logged in");
                            }
                            break;

                        case "RETR":
                            if (isLoggedIn && parts.length > 1) {
                                if (canRead(session, parts[1])) {
                                    handleRetr(writer, resolvePath(session.currentPath, parts[1]), session);
                                } else {
                                    writer.println("550 Permission denied");
                                }
                            } else {
                                writer.println("530 Not logged in");
                            }
                            break;

                        case "STOR":
                            if (isLoggedIn && parts.length > 1) {
                                if (canWrite(session, parts[1])) {
                                    handleStore(writer, resolvePath(session.currentPath, parts[1]), session);
                                } else {
                                    writer.println("550 Permission denied");
                                }
                            } else {
                                writer.println("530 Not logged in");
                            }
                            break;

                        case "TYPE":
                            // 支持二进制传输模式
                            if (isLoggedIn) {
                                writer.println("200 Type set to I");
                            } else {
                                writer.println("530 Not logged in");
                            }
                            break;

                        case "PWD":
                            if (isLoggedIn) {
                                writer.println("257 \"" + session.currentPath + "\" is current directory");
                            } else {
                                writer.println("530 Not logged in");
                            }
                            break;

                        case "CWD":
                            if (isLoggedIn && parts.length > 1) {
                                handleCwd(writer, parts[1], session);
                            } else {
                                writer.println("530 Not logged in");
                            }
                            break;

                        case "QUIT":
                            writer.println("221 Goodbye");
                            return;

                        default:
                            writer.println("502 Command not implemented");
                            log.debug("未实现的命令: {}", cmd);
                    }
                }
            } catch (IOException e) {
                log.error("处理客户端连接时发生错误: {}", e.getMessage(), e);
            } finally {
                clientSessions.remove(clientSocket);
                try {
                    if (!clientSocket.isClosed()) {
                        clientSocket.close();
                    }
                } catch (IOException e) {
                    log.error("关闭客户端连接时发生错误: {}", e.getMessage(), e);
                }
            }
        });
    }

    private void handleList(PrintWriter writer, String path, ClientSession session) {
        try (ServerSocket dataSocket = new ServerSocket(dataPort)) {
            writer.println("150 Opening data connection");
            Socket dataConnection = dataSocket.accept();
            try (PrintWriter dataWriter = new PrintWriter(
                    new OutputStreamWriter(dataConnection.getOutputStream()), true)) {

                // 处理路径
                if (path == null || path.trim().isEmpty()) {
                    path = "/";
                }
                path = path.replace("//", "/");
                
                // 构建完整的文件系统路径
                File directory = new File("/ftp" + path);
                log.debug("请求列出目录内容: {}", directory.getAbsolutePath());

                if (!directory.exists() || !directory.isDirectory()) {
                    writer.println("550 Directory not found");
                    return;
                }

                File[] files = directory.listFiles();
                if (files != null) {
                    for (File file : files) {
                        // 跳过 . 和 .. 目录
                        if (file.getName().equals(".") || file.getName().equals("..")) {
                            continue;
                        }

                        // 构建文件信息字符串
                        String fileType = file.isDirectory() ? "d" : "-";
                        String permissions = "rwxrwxrwx";  // 777 权限
                        String owner = "root";
                        String group = "root";
                        long size = file.length();
                        String timestamp = new SimpleDateFormat("MMM dd HH:mm").format(file.lastModified());
                        String name = file.getName();

                        String fileInfo = String.format("%s%s %4d %-8s %-8s %8d %s %s",
                                fileType, permissions, 1, owner, group, size, timestamp, name);

                        dataWriter.println(fileInfo);
                        log.debug("发送文件信息: {}", fileInfo);
                    }
                }
            } finally {
                try {
                    dataConnection.close();
                } catch (IOException e) {
                    log.error("关闭数据连接时发生错误", e);
                }
            }
            writer.println("226 Transfer complete");
        } catch (IOException e) {
            log.error("列出文件时发生错误: {}", e.getMessage(), e);
            writer.println("425 Can't open data connection");
        }
    }

    private void handleRetr(PrintWriter writer, String filename, ClientSession session) {
        if (!canRead(session, filename)) {
            writer.println("550 Permission denied");
            log.debug("文件下载权限不足: {} (用户: {})", filename, session.username);
            return;
        }

        File file = new File("/ftp" + filename);
        if (!file.exists() || !file.isFile()) {
            writer.println("550 File not found");
            log.debug("文件不存在: {}", filename);
            return;
        }

        try (ServerSocket dataSocket = new ServerSocket(dataPort)) {
            writer.println("150 Opening data connection for " + filename);
            log.debug("等待数据连接...");
            
            Socket dataConnection = dataSocket.accept();
            log.debug("数据连接已建立");
            
            try (FileInputStream fis = new FileInputStream(file);
                 OutputStream os = dataConnection.getOutputStream()) {
                
                byte[] buffer = new byte[8192];
                int bytesRead;
                long totalBytes = 0;
                
                while ((bytesRead = fis.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                    totalBytes += bytesRead;
                }
                os.flush();
                
                log.debug("文件下载完成: {}, 总字节数: {} (用户: {})", filename, totalBytes, session.username);
                writer.println("226 Transfer complete");
                
            } finally {
                try {
                    dataConnection.close();
                    log.debug("数据连接已关闭");
                } catch (IOException e) {
                    log.error("关闭数据连接时发生错误", e);
                }
            }
        } catch (IOException e) {
            log.error("文件下载失败: {}", e.getMessage(), e);
            writer.println("425 Can't open data connection");
        }
    }

    private void handleStore(PrintWriter writer, String filename, ClientSession session) {
        if (!canWrite(session, filename)) {
            writer.println("550 Permission denied");
            log.debug("文件上传权限不足: {} (用户: {})", filename, session.username);
            return;
        }

        filename = filename.replace("//", "/");
        File file = new File("/ftp" + filename);
        File parentDir = file.getParentFile();

        log.debug("开始处理文件上传: {} (用户: {})", filename, session.username);

        if (!parentDir.exists() && !parentDir.mkdirs()) {
            log.error("无法创建目录: {}", parentDir.getAbsolutePath());
            writer.println("550 Failed to create directory");
            return;
        }

        try (ServerSocket dataSocket = new ServerSocket(dataPort)) {
            dataSocket.setSoTimeout(30000);
            writer.println("150 Opening data connection for " + filename);
            log.debug("等待数据连接...");
            
            Socket dataConnection = dataSocket.accept();
            dataConnection.setSoTimeout(30000);
            log.debug("数据连接已建立");
            
            try (FileOutputStream fos = new FileOutputStream(file);
                 InputStream is = dataConnection.getInputStream()) {
                
                byte[] buffer = new byte[8192];
                int bytesRead;
                long totalBytes = 0;
                
                while ((bytesRead = is.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    totalBytes += bytesRead;
                }
                fos.flush();
                
                // 即使是空文件也设置权限
                try {
                    ProcessBuilder pb = new ProcessBuilder(
                        "sh", "-c",
                        "chmod 666 " + file.getAbsolutePath() + " && " +
                        "chown root:root " + file.getAbsolutePath()
                    );
                    Process process = pb.start();
                    int exitCode = process.waitFor();
                    
                    if (exitCode == 0) {
                        log.debug("文件权限设置成功: {}", file.getAbsolutePath());
                    } else {
                        log.warn("文件权限设置失败，退出码: {}", exitCode);
                    }
                } catch (Exception e) {
                    log.error("设置文件权限失败: {}", e.getMessage(), e);
                }
                
                log.info("文件上传完成: {}, 总字节数: {} (用户: {})", filename, totalBytes, session.username);
                writer.println("226 Transfer complete");
                
            } catch (IOException e) {
                log.error("文件写入失败: {}", e.getMessage(), e);
                writer.println("550 Failed to save file");
                if (file.exists()) {
                    file.delete();
                }
            } finally {
                try {
                    dataConnection.close();
                    log.debug("数据连接已关闭");
                } catch (IOException e) {
                    log.error("关闭数据连接时发生错误", e);
                }
            }
        } catch (IOException e) {
            log.error("创建数据连接失败: {}", e.getMessage(), e);
            writer.println("425 Can't open data connection");
        }
    }

    private void handleMkd(PrintWriter writer, String dirname, ClientSession session) {
        if (!canWrite(session, dirname)) {
            writer.println("550 Permission denied");
            return;
        }

        String fullPath = resolvePath(session.currentPath, dirname);
        File newDir = new File("/ftp" + fullPath);
        if (newDir.mkdir()) {
            writer.println("257 Directory created");
            log.debug("创建目录成功: {} (用户: {})", dirname, session.username);
        } else {
            writer.println("550 Failed to create directory");
            log.error("创建目录失败: {} (用户: {})", dirname, session.username);
        }
    }

    private void handleRmd(PrintWriter writer, String dirname, ClientSession session) {
        if (!canDelete(session, dirname)) {
            writer.println("550 Permission denied");
            return;
        }

        String fullPath = resolvePath(session.currentPath, dirname);
        File dir = new File("/ftp" + fullPath);
        if (dir.isDirectory() && dir.delete()) {
            writer.println("250 Directory removed");
            log.debug("删除目录成功: {} (用户: {})", dirname, session.username);
        } else {
            writer.println("550 Failed to remove directory");
            log.error("删除目录失败: {} (用户: {})", dirname, session.username);
        }
    }

    private void handleDele(PrintWriter writer, String filename, ClientSession session) {
        if (!canDelete(session, filename)) {
            writer.println("550 Permission denied");
            return;
        }

        String fullPath = resolvePath(session.currentPath, filename);
        File file = new File("/ftp" + fullPath);
        if (file.isFile() && file.delete()) {
            writer.println("250 File deleted");
            log.debug("删除文件成功: {} (用户: {})", filename, session.username);
        } else {
            writer.println("550 Failed to delete file");
            log.error("删除文件失败: {} (用户: {})", filename, session.username);
        }
    }

    private void handleCwd(PrintWriter writer, String path, ClientSession session) {
        String newPath = resolvePath(session.currentPath, path);
        File dir = new File("/ftp" + newPath);
        
        if (dir.isDirectory() && canAccess(session, newPath)) {
            session.currentPath = newPath;
            writer.println("250 Directory changed to " + newPath);
            log.debug("切换目录成功: {} (用户: {})", newPath, session.username);
        } else {
            writer.println("550 Failed to change directory");
            log.error("切换目录失败: {} (用户: {})", newPath, session.username);
        }
    }

    private boolean canAccess(ClientSession session, String path) {
        if (session.isAnonymous) {
            // 匿名用户只能访问其主目录
            return path.startsWith(anonymousHome);
        }
        
        // 普通用户可以访问：
        // 1. 自己的目录
        // 2. public 目录
        // 3. 根目录（只读）
        return path.startsWith("/" + session.username) || 
               path.startsWith("/public") ||
               "/".equals(path);
    }

    private boolean canRead(ClientSession session, String path) {
        return canAccess(session, resolvePath(session.currentPath, path));
    }

    private boolean canWrite(ClientSession session, String path) {
        if (session.isAnonymous) {
            // 根据配置决定匿名用户是否可以上传
            return anonymousUpload && path.startsWith(anonymousHome);
        }
        
        String resolvedPath = resolvePath(session.currentPath, path);
        // 用户只能在自己的目录下写入
        return resolvedPath.startsWith("/" + session.username);
    }

    private boolean canDelete(ClientSession session, String path) {
        if (session.isAnonymous) {
            return false; // 匿名用户不能删除任何文件
        }
        
        String resolvedPath = resolvePath(session.currentPath, path);
        // 用户只能删除自己目录下的文件
        return resolvedPath.startsWith("/" + session.username);
    }

    private String resolvePath(String currentPath, String newPath) {
        if (newPath.startsWith("/")) {
            return newPath;
        }
        
        if ("..".equals(newPath)) {
            int lastSlash = currentPath.lastIndexOf('/');
            return lastSlash > 0 ? currentPath.substring(0, lastSlash) : "/";
        }
        
        return (currentPath.endsWith("/") ? currentPath : currentPath + "/") + newPath;
    }

    private void createUserDirectory(String username) {
        File userDir = new File("/ftp/" + username);
        if (!userDir.exists() && userDir.mkdir()) {
            log.info("创建用户目录: {}", userDir.getAbsolutePath());
            // 设置目录权限
            userDir.setReadable(true, false);
            userDir.setWritable(true, false);
            userDir.setExecutable(true, false);
        }
    }

    private void createDirectory(String path) {
        File dir = new File(path);
        if (!dir.exists() && dir.mkdirs()) {
            log.info("创建目录: {}", path);
            dir.setReadable(true, false);
            dir.setWritable(true, false);
            dir.setExecutable(true, false);
        }
    }

    private void ensureDirectoryStructure() {
        // 检查并创建必要的目录，但不删除现有内容
        setupDirectory("/ftp");
        setupDirectory("/ftp/public");
        setupDirectory("/ftp/admin");
        setupDirectory("/ftp/user");
        setupDirectory("/ftp/test");
        log.info("已确保基本目录结构存在");
    }
} 