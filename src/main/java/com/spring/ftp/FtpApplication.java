package com.spring.ftp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class FtpApplication {

    public static void main(String[] args) {
        SpringApplication.run(FtpApplication.class, args);
        System.out.println("FTP客户端已启动，请访问: http://localhost:8080/ftp/login");
    }

}
