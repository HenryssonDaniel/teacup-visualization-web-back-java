package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.Message;
import javax.mail.Message.RecipientType;
import javax.mail.MessagingException;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;

class EmailClientImpl implements EmailClient {
  private static final Logger LOGGER = Logger.getLogger(EmailClientImpl.class.getName());
  private final Properties properties;

  EmailClientImpl(Properties properties) {
    this.properties = new Properties(properties);
  }

  @Override
  public void send(String content, Message message, String subject, String to, Transport transport)
      throws MessagingException {
    LOGGER.log(Level.FINE, "Log in");

    message.setFrom(new InternetAddress(properties.getProperty("smtp.from")));
    message.setRecipients(RecipientType.TO, InternetAddress.parse(to));
    message.setSubject(subject + " your Teacup account");
    message.setText(content);

    transport.connect();
    transport.sendMessage(message, message.getAllRecipients());
  }
}
