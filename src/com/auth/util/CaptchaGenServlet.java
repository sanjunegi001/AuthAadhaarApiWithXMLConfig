/*
 * 
 */
package com.auth.util;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
 
import java.awt.image.BufferedImage;
 
import javax.imageio.ImageIO;
import javax.servlet.http.*;
 
import java.io.*;
 
// TODO: Auto-generated Javadoc
/**
 * The Class CaptchaGenServlet.
 */
public class CaptchaGenServlet extends HttpServlet {
 
         /** The Constant FILE_TYPE. */
         public static final String FILE_TYPE = "jpeg";
 
        /* (non-Javadoc)
         * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
         */
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response)
                        throws ServletException, IOException {
 
            response.setHeader("Cache-Control", "no-cache");
            response.setDateHeader("Expires", 0);
            response.setHeader("Pragma", "no-cache");
            response.setDateHeader("Max-Age", 0);
 
            String captchaStr="";
 
       
 
            captchaStr=Util.generateCaptchaTextMethod2(6);
 
            try {
 
                int width=100;      int height=40;
 
                Color bg = new Color(255,255,255);
                Color fg = new Color(000,000,000);
 
                Font font = new Font("Arial", Font.BOLD, 20);
                BufferedImage cpimg =new BufferedImage(width,height,BufferedImage.OPAQUE);
                Graphics g = cpimg.createGraphics();
 
                g.setFont(font);
                g.setColor(bg);
                g.fillRect(0, 0, width, height);
                g.setColor(fg);
                g.drawString(captchaStr,10,25);   
 
                HttpSession session = request.getSession(true);
                session.setAttribute("CAPTCHA", captchaStr);
 
               OutputStream outputStream = response.getOutputStream();
 
               ImageIO.write(cpimg, FILE_TYPE, outputStream);
               outputStream.close();
 
            } catch (Exception e) {
                    e.printStackTrace();
            }
        }
 
        /* (non-Javadoc)
         * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
         */
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                        throws ServletException, IOException {
            doPost(request, response);
        }
 
 }