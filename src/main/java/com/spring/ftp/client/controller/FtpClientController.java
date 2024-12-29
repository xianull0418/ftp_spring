package com.spring.ftp.client.controller;

import com.spring.ftp.client.service.FtpClientService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PreDestroy;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Controller
@RequestMapping("/ftp")
public class FtpClientController {

    @Autowired
    private FtpClientService ftpClientService;

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/connect")
    public String connect(@RequestParam String host,
                         @RequestParam int port,
                         @RequestParam String username,
                         @RequestParam String password,
                         HttpSession session,
                         Model model) {
        boolean connected = ftpClientService.connect(host, port, username, password);
        if (connected) {
            session.setAttribute("connected", true);
            try {
                List<FtpClientService.FileInfo> files = ftpClientService.listFiles("/");
                model.addAttribute("files", files);
                model.addAttribute("currentPath", "/");
                return "files";
            } catch (IOException e) {
                model.addAttribute("error", "无法获取文件列表: " + e.getMessage());
                return "login";
            }
        } else {
            model.addAttribute("error", "连接失败");
            return "login";
        }
    }

    @GetMapping("/files")
    public String listFiles(@RequestParam(defaultValue = "/") String path,
                          Model model,
                          HttpSession session) {
        if (session.getAttribute("connected") == null) {
            return "redirect:/ftp/login";
        }

        try {
            path = path.replace("//", "/");
            List<FtpClientService.FileInfo> files = ftpClientService.listFiles(path);
            model.addAttribute("files", files);
            model.addAttribute("currentPath", path);
            return "files";
        } catch (IOException e) {
            log.error("获取文件列表失败", e);
            model.addAttribute("error", "获取文件列表失败: " + e.getMessage());
            return "files";
        }
    }

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file,
                            @RequestParam("path") String path,
                            Model model,
                            HttpSession session) {
        if (session.getAttribute("connected") == null) {
            return "redirect:/ftp/login";
        }

        if (file.isEmpty()) {
            model.addAttribute("error", "请选择要上传的文件");
            return "redirect:/ftp/files?path=" + path;
        }

        try {
            String filename = path + "/" + file.getOriginalFilename();
            filename = filename.replace("//", "/");
            log.info("开始上传文件: {}", filename);
            
            try (InputStream is = file.getInputStream()) {
                boolean uploaded = ftpClientService.uploadFile(filename, is);
                if (!uploaded) {
                    log.error("文件上传失败: {}", filename);
                    model.addAttribute("error", "文件上传失败，可能是权限不足");
                } else {
                    log.info("文件上传成功: {}", filename);
                }
            }
        } catch (IOException e) {
            log.error("文件上传失败", e);
            model.addAttribute("error", "文件上传失败: " + e.getMessage());
        }

        return "redirect:/ftp/files?path=" + path;
    }

    @GetMapping("/download")
    public void downloadFile(@RequestParam String path,
                           HttpServletResponse response,
                           HttpSession session) throws IOException {
        if (session.getAttribute("connected") == null) {
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("请先登录");
            return;
        }

        path = path.replace("//", "/");
        String fileName = path.substring(path.lastIndexOf('/') + 1);

        try (InputStream is = ftpClientService.downloadFile(path)) {
            if (is == null) {
                response.setContentType("text/plain;charset=UTF-8");
                response.getWriter().write("无法下载文件，可能是权限不足或文件不存在");
                return;
            }

            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + 
                new String(fileName.getBytes("UTF-8"), "ISO-8859-1") + "\"");

            try (OutputStream os = response.getOutputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
                os.flush();
            }
        } catch (IOException e) {
            log.error("文件下载失败: {}", e.getMessage(), e);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("下载失败：" + e.getMessage());
        }
    }

    @GetMapping("/disconnect")
    public String disconnect(HttpSession session) {
        try {
            ftpClientService.disconnect();
            session.removeAttribute("connected");
            log.info("已断开FTP连接");
        } catch (Exception e) {
            log.error("断开FTP连接时发生错误", e);
        }
        return "redirect:/ftp/login";
    }

    @PreDestroy
    public void cleanup() {
        try {
            ftpClientService.disconnect();
            log.info("应用程序关闭时断开FTP连接");
        } catch (Exception e) {
            log.error("清理资源时发生错误", e);
        }
    }
} 