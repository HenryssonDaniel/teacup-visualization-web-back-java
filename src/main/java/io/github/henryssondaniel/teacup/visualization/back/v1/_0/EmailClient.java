package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Transport;

@FunctionalInterface
interface EmailClient {
  void send(String content, Message message, String subject, String to, Transport transport)
      throws MessagingException;
}
