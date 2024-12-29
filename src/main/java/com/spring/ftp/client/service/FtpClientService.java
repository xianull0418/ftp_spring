package com.spring.ftp.client.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.annotation.PreDestroy;
import java.io.*;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class FtpClientService {
    
    private Socket controlSocket;
    private PrintWriter writer;
    private BufferedReader reader;
    private Socket dataSocket;
    
    public boolean connect(String host, int port, String username, String password) {
        try {
            log.info("正在连接FTP服务器: {}:{}", host, port);
            controlSocket = new Socket(host, port);
            controlSocket.setSoTimeout(30000);
            controlSocket.setKeepAlive(true);
            
            writer = new PrintWriter(new OutputStreamWriter(controlSocket.getOutputStream()), true);
            reader = new BufferedReader(new InputStreamReader(controlSocket.getInputStream()));
            
            // 读取欢迎消息
            String response = reader.readLine();
            log.info("服务器响应: {}", response);
            if (!response.startsWith("220")) {
                return false;
            }
            
            // 发送用户名
            writer.println("USER " + username);
            response = reader.readLine();
            log.info("用户名响应: {}", response);
            if (!response.startsWith("331")) {
                return false;
            }
            
            // 发送密码
            writer.println("PASS " + password);
            response = reader.readLine();
            log.info("密码响应: {}", response);
            if (!response.startsWith("230")) {
                return false;
            }
            
            log.info("FTP登录成功");
            return true;
        } catch (IOException e) {
            log.error("FTP连接失败: {}", e.getMessage(), e);
            return false;
        }
    }
    
    public List<FileInfo> listFiles(String path) throws IOException {
        List<FileInfo> files = new ArrayList<>();
        
        // 进入被动模式
        writer.println("PASV");
        String response = reader.readLine();
        if (!response.startsWith("227")) {
            throw new IOException("无法进入被动模式: " + response);
        }

        // 解析数据端口
        int[] parts = parsePortNumbers(response);
        int dataPort = parts[0] * 256 + parts[1];
        String host = controlSocket.getInetAddress().getHostAddress();

        // 发送LIST命令
        writer.println("LIST " + path);
        response = reader.readLine();
        if (!response.startsWith("150")) {
            throw new IOException("无法列出文件: " + response);
        }

        // 连接数据端口并读取文件列表
        try (Socket dataSocket = new Socket(host, dataPort)) {
            dataSocket.setSoTimeout(15000);  // 设置数据连接超时
            
            try (BufferedReader dataReader = new BufferedReader(
                    new InputStreamReader(dataSocket.getInputStream()))) {
                String line;
                while ((line = dataReader.readLine()) != null) {
                    FileInfo file = parseFileInfo(line);
                    if (file != null) {
                        files.add(file);
                    }
                }
            }
        }

        // 读取传输完成响应
        response = reader.readLine();
        if (!response.startsWith("226")) {
            throw new IOException("文件列表传输未完成: " + response);
        }

        return files;
    }
    
    public boolean uploadFile(String path, InputStream inputStream) {
        try {
            // 进入被动模式
            writer.println("PASV");
            String response = reader.readLine();
            log.debug("PASV响应: {}", response);
            if (!response.startsWith("227")) {
                return false;
            }

            // 解析数据端口
            int[] parts = parsePortNumbers(response);
            int dataPort = parts[0] * 256 + parts[1];
            String host = controlSocket.getInetAddress().getHostAddress();

            // 发送STOR命令
            writer.println("STOR " + path);
            response = reader.readLine();
            log.debug("STOR响应: {}", response);
            if (!response.startsWith("150")) {
                return false;
            }

            // 连接到数据端口并发送文件
            try (Socket dataSocket = new Socket(host, dataPort)) {
                dataSocket.setSoTimeout(30000);
                
                try (OutputStream os = dataSocket.getOutputStream()) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    long totalBytes = 0;

                    // 读取输入流中的所有数据
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        os.write(buffer, 0, bytesRead);
                        totalBytes += bytesRead;
                    }
                    os.flush();
                    
                    // 确保空文件也能正确处理
                    if (totalBytes == 0) {
                        log.debug("上传空文件");
                    }
                    
                    log.info("文件上传完成，总字节数: {}", totalBytes);
                }

                // 关闭数据连接后等待服务器的响应
                dataSocket.close();
                
                // 等待传输完成响应
                controlSocket.setSoTimeout(5000);
                response = reader.readLine();
                log.debug("传输完成响应: {}", response);
                
                // 重置回正常的超时时间
                controlSocket.setSoTimeout(30000);
                
                return response != null && response.startsWith("226");
            }
        } catch (IOException e) {
            log.error("文件上传失败: {}", e.getMessage(), e);
            try {
                controlSocket.setSoTimeout(30000);
            } catch (Exception ex) {
                log.error("重置超时设置失败", ex);
            }
            return false;
        }
    }
    
    public InputStream downloadFile(String path) throws IOException {
        dataSocket = openDataConnection("RETR " + path);
        if (dataSocket == null) {
            return null;
        }
        return dataSocket.getInputStream();
    }
    
    private Socket openDataConnection(String command) throws IOException {
        // 进入被动模式
        writer.println("PASV");
        String response = reader.readLine();
        if (!response.startsWith("227")) {
            return null;
        }
        
        // 解析数据端口
        int[] parts = parsePortNumbers(response);
        int dataPort = parts[0] * 256 + parts[1];
        
        // 发送命令
        writer.println(command);
        response = reader.readLine();
        if (!response.startsWith("150")) {
            return null;
        }
        
        // 连接数据端口
        return new Socket(controlSocket.getInetAddress(), dataPort);
    }
    
    private int[] parsePortNumbers(String pasvResponse) {
        // 从PASV响应中提取端口号
        // 响应格式: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
        int start = pasvResponse.indexOf('(');
        int end = pasvResponse.indexOf(')');
        String[] numbers = pasvResponse.substring(start + 1, end).split(",");
        return new int[]{
            Integer.parseInt(numbers[4]),
            Integer.parseInt(numbers[5])
        };
    }
    
    public void disconnect() {
        try {
            if (writer != null) {
                writer.println("QUIT");
                String response = reader.readLine();
                log.debug("服务器响应: {}", response);
                writer.close();
            }
            if (reader != null) {
                reader.close();
            }
            if (dataSocket != null && !dataSocket.isClosed()) {
                dataSocket.close();
            }
            if (controlSocket != null && !controlSocket.isClosed()) {
                controlSocket.close();
            }
            log.info("FTP连接已断开");
        } catch (IOException e) {
            log.error("断开FTP连接时发生错误: {}", e.getMessage(), e);
            throw new RuntimeException("断开连接失败", e);
        } finally {
            writer = null;
            reader = null;
            dataSocket = null;
            controlSocket = null;
        }
    }

    @PreDestroy
    public void cleanup() {
        disconnect();
    }

    private FileInfo parseFileInfo(String line) {
        // 解析FTP LIST命令返回的文件信息
        // 典型格式: "drwxr-xr-x 2 user group 4096 Dec 28 12:34 dirname"
        String[] parts = line.split("\\s+");
        if (parts.length >= 9) {
            FileInfo file = new FileInfo();
            file.setDirectory(line.startsWith("d"));
            file.setName(parts[8]);
            file.setSize(Long.parseLong(parts[4]));
            file.setTimestamp(parts[5] + " " + parts[6] + " " + parts[7]);
            return file;
        }
        return null;
    }

    public static class FileInfo {
        private String name;
        private boolean directory;
        private long size;
        private String timestamp;

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public boolean isDirectory() { return directory; }
        public void setDirectory(boolean directory) { this.directory = directory; }
        public long getSize() { return size; }
        public void setSize(long size) { this.size = size; }
        public String getTimestamp() { return timestamp; }
        public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
    }
} 